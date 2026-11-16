const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const net = require('net');
const dns = require('dns').promises;
const QRCode = require('qrcode');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 80;
const APP_TITLE = (process.env.APP_TITLE || 'LocalChat').trim() || 'LocalChat';
const APP_SUBTITLE = (process.env.APP_SUBTITLE || 'Local Network Communication').trim() || 'Local Network Communication';
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const MAX_AGE_MS = 24 * 60 * 60 * 1000; // Max 24 Hours
const RECENT_DISCONNECT_TTL_MS = 2 * 60 * 60 * 1000; // Max 2 Hours after disconnect

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

function sanitizeFilename(name) {
  const base = path.basename(String(name || 'file'));
  return base.replace(/[^\w.\-() ]+/g, '_').slice(0, 180) || 'file';
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const uniquePrefix = Date.now() + '-' + Math.round(Math.random() * 1e4);
    const safeName = sanitizeFilename(file.originalname);
    cb(null, `${uniquePrefix}-${safeName}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 * 1024 } // Max 2 GB
});

// In-memory storage
let messages = [];
const focusedTopics = new Map(); // topicId -> topicObject
const activeSockets = new Map(); // socket.id -> { ip, connectedAt }
const disconnectedUsers = new Map(); // ip -> { ip, disconnectedAt }
const linkPreviewCache = new Map();

function escapeHtmlServer(str) {
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[m]));
}

function decodeHtmlEntities(str) {
  return str
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&#x2F;/gi, '/')
    .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(Number(dec)));
}

// Check whether an IPv4 or IPv6 address belongs to private, loopback, or reserved ranges
function isPrivateOrReservedIp(rawIp) {
  let ip = (rawIp || '').trim().toLowerCase();
  if (!ip) return true;
  if (ip.startsWith('[') && ip.endsWith(']')) {
    ip = ip.slice(1, -1);
  }
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }

  const ipVersion = net.isIP(ip);
  if (ipVersion === 4) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return true;
    const [a, b] = parts;

    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8 (Private)
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
    if (a === 127) return true; // 127.0.0.0/8 (Loopback)
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 (Link-local)
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 (Private)
    if (a === 192 && b === 0 && (parts[2] === 0 || parts[2] === 2)) return true;
    if (a === 192 && b === 168) return true; // 192.168.0.0/16 (Private)
    if (a === 198 && (b === 18 || b === 19)) return true; // Benchmarking
    if (a === 198 && b === 51 && parts[2] === 100) return true;
    if (a === 203 && b === 0 && parts[2] === 113) return true;
    if (a >= 224) return true; // Multicast & Reserved
    return false;
  }

  if (ipVersion === 6) {
    if (ip === '::' || ip === '::1') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true; // Unique local fc00::/7
    if (/^fe[89ab]/.test(ip)) return true; // Link-local fe80::/10
    if (ip.startsWith('ff')) return true; // Multicast ff00::/8
    return false;
  }

  return true;
}

// Validate protocol, hostname, and DNS records to prevent SSRF into LAN/localhost
async function isSafeExternalUrl(urlObj) {
  if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
    return false;
  }

  const hostname = urlObj.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    return false;
  }

  if (net.isIP(hostname)) {
    return !isPrivateOrReservedIp(hostname);
  }

  try {
    const records = await dns.lookup(hostname, { all: true });
    if (!records || records.length === 0) return false;
    return records.every(rec => !isPrivateOrReservedIp(rec.address));
  } catch {
    return false;
  }
}

async function fetchSafeExternal(initialUrl, options, maxRedirects = 3) {
  let currentUrl = initialUrl;
  for (let i = 0; i <= maxRedirects; i++) {
    const urlObj = new URL(currentUrl);
    if (!(await isSafeExternalUrl(urlObj))) {
      throw new Error('Blocked private or unsafe URL');
    }

    const res = await fetch(urlObj.href, { ...options, redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) return res;
      currentUrl = new URL(location, urlObj.href).href;
      continue;
    }

    return res;
  }
  throw new Error('Too many redirects');
}

// Robust <meta> parser supporting multi-line attributes and varied attribute order
function parseHtmlMetadata(html) {
  const metaMap = {};
  const metaTags = html.match(/<meta\b[^>]*>/gi) || [];

  for (const tag of metaTags) {
    const attrRegex = /([a-zA-Z0-9:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
    const attrs = {};
    let match;
    while ((match = attrRegex.exec(tag)) !== null) {
      const key = match[1].toLowerCase();
      const val = match[2] ?? match[3] ?? match[4] ?? '';
      attrs[key] = val;
    }

    const metaKey = (attrs.property || attrs.name || attrs.itemprop || '').toLowerCase().trim();
    const content = (attrs.content || '').trim();
    if (metaKey && content && !metaMap[metaKey]) {
      metaMap[metaKey] = decodeHtmlEntities(content);
    }
  }

  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const pageTitle = titleMatch ? decodeHtmlEntities(titleMatch[1].replace(/\s+/g, ' ').trim()) : '';

  return { metaMap, pageTitle };
}

function extractYouTubeVideoId(urlObj) {
  const host = urlObj.hostname.replace(/^www\./i, '').toLowerCase();
  if (host === 'youtu.be') {
    const id = urlObj.pathname.split('/').filter(Boolean)[0];
    return id && /^[a-zA-Z0-9_-]{11}$/.test(id) ? id : null;
  }
  if (host === 'youtube.com' || host === 'm.youtube.com' || host === 'music.youtube.com') {
    if (urlObj.pathname === '/watch') {
      const v = urlObj.searchParams.get('v');
      return v && /^[a-zA-Z0-9_-]{11}$/.test(v) ? v : null;
    }
    const parts = urlObj.pathname.split('/').filter(Boolean);
    if (parts.length >= 2 && ['shorts', 'embed', 'live', 'v'].includes(parts[0])) {
      return /^[a-zA-Z0-9_-]{11}$/.test(parts[1]) ? parts[1] : null;
    }
  }
  return null;
}

function normalizeUrl(raw) {
  const val = (raw || '').trim();
  if (!val) return '';
  if (/^https?:\/\//i.test(val)) return val;
  return `http://${val}`;
}

function resolveAccessUrl(requestHostHeader) {
  const customQrUrl = normalizeUrl(process.env.QR_URL);
  if (customQrUrl) {
    return customQrUrl;
  }

  const manualHostIp = (process.env.HOST_IP || '').trim();
  const hostPort = (process.env.HOST_PORT || '3000').trim();
  if (manualHostIp) {
    return hostPort === '80' ? `http://${manualHostIp}` : `http://${manualHostIp}:${hostPort}`;
  }

  return requestHostHeader ? `http://${requestHostHeader}` : '';
}

function getClientIp(reqOrSocket) {
  let ip = reqOrSocket.socket?.remoteAddress || reqOrSocket.handshake?.address;

  if (TRUST_PROXY) {
    const headers = reqOrSocket.headers || reqOrSocket.handshake?.headers || {};
    const forwarded = headers['x-forwarded-for'];
    if (forwarded) {
      ip = forwarded.split(',')[0].trim();
    }
  }

  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  return ip || 'Unknown IP';
}

function getActiveUsersList() {
  const ipMap = new Map();
  for (const info of activeSockets.values()) {
    if (!ipMap.has(info.ip)) {
      ipMap.set(info.ip, {
        ip: info.ip,
        sessions: 1,
        connectedAt: info.connectedAt
      });
    } else {
      const existing = ipMap.get(info.ip);
      existing.sessions += 1;
      existing.connectedAt = Math.min(existing.connectedAt, info.connectedAt);
    }
  }
  return Array.from(ipMap.values()).sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
}

function getDisconnectedUsersList() {
  const now = Date.now();
  const activeIpSet = new Set(Array.from(activeSockets.values()).map(s => s.ip));
  const result = [];

  for (const [ip, info] of disconnectedUsers.entries()) {
    if (activeIpSet.has(ip) || (now - info.disconnectedAt) > RECENT_DISCONNECT_TTL_MS) {
      disconnectedUsers.delete(ip);
    } else {
      result.push(info);
    }
  }

  return result.sort((a, b) => b.disconnectedAt - a.disconnectedAt);
}

function broadcastActiveUsers() {
  const users = getActiveUsersList();
  const recentDisconnected = getDisconnectedUsersList();
  io.emit('active_users_update', {
    totalOnline: users.length,
    users,
    recentDisconnected
  });
}

function emitToIps(ipList, eventName, payload) {
  const targetSet = new Set(ipList);
  for (const [socketId, info] of activeSockets.entries()) {
    if (targetSet.has(info.ip)) {
      io.to(socketId).emit(eventName, payload);
    }
  }
}

function getAllActiveFocusedTopics() {
  const now = Date.now();
  const result = [];
  for (const topic of focusedTopics.values()) {
    if (now < topic.expiresAt) {
      result.push(topic);
    }
  }
  return result.sort((a, b) => b.lastActivityAt - a.lastActivityAt);
}

function clampMinutes(val, fallback) {
  const num = parseInt(val, 10);
  if (isNaN(num) || num < 1) return fallback;
  return Math.min(num, 1440);
}

function deleteFileSafe(filePath) {
  if (!filePath) return;
  fs.unlink(filePath, (err) => {
    if (err && err.code !== 'ENOENT') console.error('Failed to delete file:', err);
  });
}

// Inject APP_TITLE and APP_SUBTITLE into index.html
app.get(['/', '/index.html'], (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  fs.readFile(indexPath, 'utf8', (err, html) => {
    if (err) {
      return res.status(500).send('Failed to load application page.');
    }
    const rendered = html
      .replace(/\{\{APP_TITLE\}\}/g, escapeHtmlServer(APP_TITLE))
      .replace(/\{\{APP_SUBTITLE\}\}/g, escapeHtmlServer(APP_SUBTITLE));
    res.type('html').send(rendered);
  });
});

app.use(express.static(path.join(__dirname, 'public')));

// Serve uploaded files safely to prevent Stored XSS via HTML/SVG uploads
app.use('/uploads', express.static(UPLOAD_DIR, {
  setHeaders: (res, filePath) => {
    const filename = path.basename(filePath);
    const displayName = filename.replace(/^\d+-\d+-/, '') || filename;
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; media-src 'self'; sandbox");
    res.setHeader('Content-Disposition', `attachment; filename="${displayName.replace(/"/g, '_')}"`);
  }
}));

// Endpoint Link Preview & Thumbnail (Supports YouTube & News Portals with SSRF Protection)
app.get('/api/link-preview', async (req, res) => {
  const rawUrl = (req.query.url || '').trim();
  if (!rawUrl) return res.status(400).json({ error: 'URL is required' });

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  if (!(await isSafeExternalUrl(parsed))) {
    return res.status(400).json({ error: 'Local or private network URLs are not allowed' });
  }

  if (linkPreviewCache.has(parsed.href)) {
    return res.json(linkPreviewCache.get(parsed.href));
  }

  // Dedicated YouTube Handler via oEmbed + Thumbnail fallback
  const ytVideoId = extractYouTubeVideoId(parsed);
  if (ytVideoId) {
    const fallbackThumb = `https://i.ytimg.com/vi/${ytVideoId}/hqdefault.jpg`;
    let ytPreview = {
      url: parsed.href,
      domain: 'youtube.com',
      title: 'YouTube Video',
      description: '',
      image: fallbackThumb,
      isDirectImage: false
    };

    try {
      const oembedUrl = `https://www.youtube.com/oembed?url=${encodeURIComponent(parsed.href)}&format=json`;
      const ytRes = await fetch(oembedUrl, {
        signal: AbortSignal.timeout(5000),
        headers: { 'Accept': 'application/json' }
      });
      if (ytRes.ok) {
        const ytJson = await ytRes.json();
        ytPreview.title = (ytJson.title || 'YouTube Video').slice(0, 140);
        ytPreview.description = ytJson.author_name ? `Channel: ${ytJson.author_name}` : '';
        ytPreview.image = ytJson.thumbnail_url || fallbackThumb;
      }
    } catch {
      // Keep fallback thumbnail & title
    }

    linkPreviewCache.set(parsed.href, ytPreview);
    return res.json(ytPreview);
  }

  // General Web & News Portal Metadata Scraper
  try {
    const response = await fetchSafeExternal(parsed.href, {
      signal: AbortSignal.timeout(8000),
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/*,*/*;q=0.8',
        'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'
      }
    });

    const finalUrl = response.url || parsed.href;
    const finalParsed = new URL(finalUrl);
    const contentType = (response.headers.get('content-type') || '').toLowerCase();

    let previewData = {
      url: parsed.href,
      domain: finalParsed.hostname.replace(/^www\./i, ''),
      title: finalParsed.hostname,
      description: '',
      image: '',
      isDirectImage: false
    };

    if (contentType.startsWith('image/')) {
      previewData.title = finalParsed.pathname.split('/').pop() || finalParsed.hostname;
      previewData.image = finalUrl;
      previewData.isDirectImage = true;
    } else if (contentType.includes('text/html') && response.body) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let htmlChunk = '';
      let bytesRead = 0;
      const MAX_BYTES = 1024 * 1024; // Read up to 1 MB

      while (bytesRead < MAX_BYTES) {
        const { done, value } = await reader.read();
        if (done) break;
        bytesRead += value.byteLength;
        htmlChunk += decoder.decode(value, { stream: true });
        if (/<\/head>/i.test(htmlChunk)) break;
      }
      reader.cancel().catch(() => {});

      const { metaMap, pageTitle } = parseHtmlMetadata(htmlChunk);

      const resolvedTitle =
        metaMap['og:title'] ||
        metaMap['twitter:title'] ||
        metaMap['title'] ||
        pageTitle ||
        finalParsed.hostname;

      const resolvedDesc =
        metaMap['og:description'] ||
        metaMap['twitter:description'] ||
        metaMap['description'] ||
        '';

      let resolvedImg =
        metaMap['og:image:secure_url'] ||
        metaMap['og:image'] ||
        metaMap['twitter:image:src'] ||
        metaMap['twitter:image'] ||
        metaMap['image'] ||
        '';

      if (resolvedImg) {
        try {
          resolvedImg = new URL(resolvedImg, finalUrl).href;
        } catch {
          resolvedImg = '';
        }
      }

      previewData.title = resolvedTitle.slice(0, 140);
      previewData.description = resolvedDesc.slice(0, 200);
      previewData.image = resolvedImg;
    } else {
      previewData.title = finalParsed.pathname.split('/').pop() || finalParsed.hostname;
      previewData.description = contentType || 'External Link';
    }

    if (linkPreviewCache.size >= 250) {
      const firstKey = linkPreviewCache.keys().next().value;
      linkPreviewCache.delete(firstKey);
    }
    linkPreviewCache.set(parsed.href, previewData);

    res.json(previewData);
  } catch {
    res.status(502).json({ error: 'Preview unavailable' });
  }
});

// Send Text and/or File Message
app.post('/api/messages', upload.single('file'), (req, res) => {
  const text = req.body.text ? req.body.text.trim() : '';
  const file = req.file;
  const roomId = (req.body.roomId || 'global').trim();
  const disablePreview = req.body.disablePreview === 'true';
  const clientIp = getClientIp(req);

  if (!text && !file) {
    return res.status(400).json({ error: 'Message or file cannot be empty.' });
  }

  const now = Date.now();
  let ttlMs = MAX_AGE_MS;
  let targetTopic = null;

  if (roomId !== 'global') {
    targetTopic = focusedTopics.get(roomId);
    if (!targetTopic || now >= targetTopic.expiresAt) {
      if (file) deleteFileSafe(file.path);
      return res.status(404).json({ error: 'Focused Topic not found or has expired.' });
    }
    if (!targetTopic.members.includes(clientIp)) {
      if (file) deleteFileSafe(file.path);
      return res.status(403).json({ error: 'You are not a member of this Focused Topic.' });
    }

    ttlMs = Math.min(targetTopic.messageTtlMinutes * 60 * 1000, MAX_AGE_MS);
    targetTopic.lastActivityAt = now;
    targetTopic.expiresAt = now + Math.min(targetTopic.inactivityTtlMinutes * 60 * 1000, MAX_AGE_MS);
  } else {
    const ttlMinutes = clampMinutes(req.body.ttl, 1440);
    ttlMs = ttlMinutes * 60 * 1000;
  }

  const newMessage = {
    id: now.toString() + Math.random().toString(36).substring(2, 6),
    roomId,
    ip: clientIp,
    text,
    disablePreview,
    file: file ? {
      originalName: sanitizeFilename(file.originalname),
      url: `/uploads/${file.filename}`,
      size: file.size,
      mimeType: file.mimetype || ''
    } : null,
    filePath: file ? file.path : null,
    timestamp: now,
    expiresAt: now + ttlMs
  };

  messages.push(newMessage);

  const { filePath, ...publicMessage } = newMessage;

  if (targetTopic) {
    emitToIps(targetTopic.members, 'new_message', publicMessage);
    io.emit('topic_updated', targetTopic);
  } else {
    io.emit('new_message', publicMessage);
  }

  res.status(201).json(publicMessage);
});

// WebSocket Connection
io.on('connection', async (socket) => {
  const clientIp = getClientIp(socket);
  const now = Date.now();

  disconnectedUsers.delete(clientIp);
  activeSockets.set(socket.id, { ip: clientIp, connectedAt: now });
  broadcastActiveUsers();

  const accessUrl = resolveAccessUrl(socket.handshake.headers.host);
  let qrDataUrl = '';
  if (accessUrl) {
    try {
      qrDataUrl = await QRCode.toDataURL(accessUrl, {
        width: 240,
        margin: 2,
        color: { dark: '#0B3B68', light: '#FFFFFF' }
      });
    } catch (err) {
      console.error('Failed to generate QR:', err);
    }
  }

  const allTopics = getAllActiveFocusedTopics();
  const joinedTopicIds = new Set(
    allTopics.filter(t => t.members.includes(clientIp)).map(t => t.id)
  );
  const allowedRoomIds = new Set(['global', ...joinedTopicIds]);

  const activeMessages = messages
    .filter(m => now < m.expiresAt && allowedRoomIds.has(m.roomId))
    .map(({ filePath, ...rest }) => rest);

  const activeUsers = getActiveUsersList();
  const recentDisconnected = getDisconnectedUsersList();

  socket.emit('init', {
    appTitle: APP_TITLE,
    appSubtitle: APP_SUBTITLE,
    yourIp: clientIp,
    accessUrl,
    qrDataUrl,
    activeUsers: {
      totalOnline: activeUsers.length,
      users: activeUsers,
      recentDisconnected
    },
    topics: allTopics,
    messages: activeMessages
  });

  // Delete Message (Sender or Focused Topic Admin)
  socket.on('delete_message', ({ messageId }, callback) => {
    const idx = messages.findIndex(m => m.id === messageId);
    if (idx === -1) {
      return callback?.({ ok: false, error: 'Message not found or already expired.' });
    }

    const targetMsg = messages[idx];
    let canDelete = targetMsg.ip === clientIp;

    if (!canDelete && targetMsg.roomId !== 'global') {
      const top = focusedTopics.get(targetMsg.roomId);
      if (top && top.adminIp === clientIp) {
        canDelete = true;
      }
    }

    if (!canDelete) {
      return callback?.({ ok: false, error: 'You do not have permission to delete this message.' });
    }

    messages.splice(idx, 1);
    deleteFileSafe(targetMsg.filePath);

    if (targetMsg.roomId !== 'global') {
      const top = focusedTopics.get(targetMsg.roomId);
      if (top) {
        emitToIps(top.members, 'message_deleted', { messageId });
      }
    } else {
      io.emit('message_deleted', { messageId });
    }

    callback?.({ ok: true });
  });

  // Create New Focused Topic
  socket.on('create_topic', (payload = {}, callback) => {
    const name = (payload.name || '').trim().slice(0, 40);
    if (!name) {
      if (callback) callback({ ok: false, error: 'Focused Topic name is required.' });
      return;
    }

    const inactivityTtlMinutes = clampMinutes(payload.inactivityTtlMinutes, 1440);
    const messageTtlMinutes = clampMinutes(payload.messageTtlMinutes, 1440);
    const selectedIps = Array.isArray(payload.members) ? payload.members : [];

    const memberSet = new Set([clientIp]);
    for (const ip of selectedIps) {
      if (typeof ip === 'string' && ip.trim()) {
        memberSet.add(ip.trim());
      }
    }

    const createdAt = Date.now();
    const topicId = 'top_' + createdAt.toString(36) + Math.random().toString(36).substring(2, 6);

    const newTopic = {
      id: topicId,
      name,
      adminIp: clientIp,
      members: Array.from(memberSet),
      pendingRequests: [],
      inactivityTtlMinutes,
      messageTtlMinutes,
      createdAt,
      lastActivityAt: createdAt,
      expiresAt: createdAt + inactivityTtlMinutes * 60 * 1000
    };

    focusedTopics.set(topicId, newTopic);
    io.emit('topic_created', newTopic);

    if (callback) callback({ ok: true, topic: newTopic });
  });

  // Non-member: Request to Join a Focused Topic
  socket.on('topic_request_join', ({ topicId }, callback) => {
    const topic = focusedTopics.get(topicId);
    const nowTs = Date.now();
    if (!topic || nowTs >= topic.expiresAt) {
      return callback?.({ ok: false, error: 'Focused Topic not found or has expired.' });
    }
    if (topic.members.includes(clientIp)) {
      return callback?.({ ok: false, error: 'You are already a member of this Focused Topic.' });
    }

    if (!Array.isArray(topic.pendingRequests)) {
      topic.pendingRequests = [];
    }

    if (!topic.pendingRequests.includes(clientIp)) {
      topic.pendingRequests.push(clientIp);
      io.emit('topic_updated', topic);
      emitToIps([topic.adminIp], 'topic_join_requested', {
        topicId: topic.id,
        topicName: topic.name,
        requesterIp: clientIp
      });
    }

    callback?.({ ok: true, topic });
  });

  // Admin: Approve or Decline Join Request
  socket.on('topic_handle_join_request', ({ topicId, targetIp, approve }, callback) => {
    const topic = focusedTopics.get(topicId);
    if (!topic) return callback?.({ ok: false, error: 'Focused Topic not found.' });
    if (topic.adminIp !== clientIp) return callback?.({ ok: false, error: 'Only admin can manage join requests.' });

    const cleanIp = (targetIp || '').trim();
    topic.pendingRequests = (topic.pendingRequests || []).filter(ip => ip !== cleanIp);

    if (approve && cleanIp && !topic.members.includes(cleanIp)) {
      topic.members.push(cleanIp);
      const nowTs = Date.now();
      topic.lastActivityAt = nowTs;
      topic.expiresAt = nowTs + topic.inactivityTtlMinutes * 60 * 1000;

      const topicMsgs = messages
        .filter(m => m.roomId === topicId && nowTs < m.expiresAt)
        .map(({ filePath, ...rest }) => rest);

      emitToIps([cleanIp], 'topic_invited', { topic, messages: topicMsgs, fromRequest: true });
    } else if (!approve && cleanIp) {
      emitToIps([cleanIp], 'topic_join_declined', { topicId: topic.id, topicName: topic.name });
    }

    io.emit('topic_updated', topic);
    callback?.({ ok: true, topic });
  });

  // Admin: Add Member Directly to Focused Topic
  socket.on('topic_add_member', ({ topicId, targetIp }, callback) => {
    const topic = focusedTopics.get(topicId);
    if (!topic) return callback?.({ ok: false, error: 'Focused Topic not found.' });
    if (topic.adminIp !== clientIp) return callback?.({ ok: false, error: 'Only admin can add members.' });

    const cleanIp = (targetIp || '').trim();
    if (!cleanIp) return callback?.({ ok: false, error: 'Invalid IP address.' });

    topic.pendingRequests = (topic.pendingRequests || []).filter(ip => ip !== cleanIp);

    if (!topic.members.includes(cleanIp)) {
      topic.members.push(cleanIp);
      const nowTs = Date.now();
      topic.lastActivityAt = nowTs;
      topic.expiresAt = nowTs + topic.inactivityTtlMinutes * 60 * 1000;

      const topicMsgs = messages
        .filter(m => m.roomId === topicId && nowTs < m.expiresAt)
        .map(({ filePath, ...rest }) => rest);

      emitToIps([cleanIp], 'topic_invited', { topic, messages: topicMsgs, fromRequest: false });
      io.emit('topic_updated', topic);
    }

    callback?.({ ok: true, topic });
  });

  // Admin: Remove Member from Focused Topic
  socket.on('topic_remove_member', ({ topicId, targetIp }, callback) => {
    const topic = focusedTopics.get(topicId);
    if (!topic) return callback?.({ ok: false, error: 'Focused Topic not found.' });
    if (topic.adminIp !== clientIp) return callback?.({ ok: false, error: 'Only admin can remove members.' });
    if (targetIp === topic.adminIp) return callback?.({ ok: false, error: 'Admin cannot remove themselves.' });

    if (topic.members.includes(targetIp)) {
      topic.members = topic.members.filter(ip => ip !== targetIp);
      const nowTs = Date.now();
      topic.lastActivityAt = nowTs;
      topic.expiresAt = nowTs + topic.inactivityTtlMinutes * 60 * 1000;

      emitToIps([targetIp], 'kicked_from_topic', { topicId, topicName: topic.name });
      io.emit('topic_updated', topic);
    }

    callback?.({ ok: true, topic });
  });

  // Admin: Update Focused Topic Settings
  socket.on('topic_update_settings', ({ topicId, inactivityTtlMinutes, messageTtlMinutes }, callback) => {
    const topic = focusedTopics.get(topicId);
    if (!topic) return callback?.({ ok: false, error: 'Focused Topic not found.' });
    if (topic.adminIp !== clientIp) return callback?.({ ok: false, error: 'Only admin can update Focused Topic settings.' });

    const nowTs = Date.now();
    const expiredMsgIds = [];

    if (inactivityTtlMinutes !== undefined) {
      topic.inactivityTtlMinutes = clampMinutes(inactivityTtlMinutes, topic.inactivityTtlMinutes);
    }

    if (messageTtlMinutes !== undefined) {
      topic.messageTtlMinutes = clampMinutes(messageTtlMinutes, topic.messageTtlMinutes);
      const newMsgTtlMs = topic.messageTtlMinutes * 60 * 1000;

      messages = messages.filter(msg => {
        if (msg.roomId === topicId) {
          msg.expiresAt = Math.min(msg.timestamp + newMsgTtlMs, msg.timestamp + MAX_AGE_MS);
          if (nowTs >= msg.expiresAt) {
            expiredMsgIds.push(msg.id);
            deleteFileSafe(msg.filePath);
            return false;
          }
        }
        return true;
      });
    }

    topic.lastActivityAt = nowTs;
    topic.expiresAt = nowTs + topic.inactivityTtlMinutes * 60 * 1000;

    if (expiredMsgIds.length > 0) {
      emitToIps(topic.members, 'messages_expired', expiredMsgIds);
    }

    const updatedTopicMsgs = messages
      .filter(m => m.roomId === topicId && nowTs < m.expiresAt)
      .map(({ filePath, ...rest }) => rest);

    io.emit('topic_updated', topic);
    emitToIps(topic.members, 'topic_messages_synced', { topicId, messages: updatedTopicMsgs });

    callback?.({ ok: true, topic });
  });

  socket.on('disconnect', () => {
    activeSockets.delete(socket.id);
    const stillConnected = Array.from(activeSockets.values()).some(s => s.ip === clientIp);
    if (!stillConnected) {
      disconnectedUsers.set(clientIp, {
        ip: clientIp,
        disconnectedAt: Date.now()
      });
    }
    broadcastActiveUsers();
  });
});

// Cleanup expired messages, Focused Topics, and 2-hour disconnected users every 15 seconds
setInterval(() => {
  const now = Date.now();
  const expiredTopicIds = [];

  for (const [topicId, topic] of focusedTopics.entries()) {
    if (now >= topic.expiresAt) {
      expiredTopicIds.push(topicId);
      io.emit('topic_expired', { topicId, topicName: topic.name });
      focusedTopics.delete(topicId);
    }
  }

  const expiredMsgIds = [];
  messages = messages.filter(msg => {
    const isExpired = now >= msg.expiresAt || expiredTopicIds.includes(msg.roomId);
    if (isExpired) {
      expiredMsgIds.push(msg.id);
      deleteFileSafe(msg.filePath);
    }
    return !isExpired;
  });

  if (expiredMsgIds.length > 0) {
    io.emit('messages_expired', expiredMsgIds);
  }

  let disconnectedChanged = false;
  for (const [ip, info] of disconnectedUsers.entries()) {
    if ((now - info.disconnectedAt) > RECENT_DISCONNECT_TTL_MS) {
      disconnectedUsers.delete(ip);
      disconnectedChanged = true;
    }
  }
  if (disconnectedChanged) {
    broadcastActiveUsers();
  }
}, 15 * 1000);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`${APP_TITLE} v0.1.0 listening on port ${PORT}`);
});