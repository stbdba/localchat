# LocalChat

A lightweight, self-hosted Docker web application for instant text and file sharing across a local area network (LAN / Wi-Fi) without requiring user registration or external databases. Devices on the same network are automatically identified by their local IP address, and all shared messages/files automatically expire within a maximum of 24 hours.

---

## Features

- **Zero Registration:** Open the browser on any phone, tablet, or computer connected to the same Wi-Fi/LAN and start sharing immediately.
- **IP-Based Device Identification:** Automatically distinguishes connected devices by their local IP address with color-coded sender indicators.
- **Real-Time Text & File Transfer:** Powered by WebSockets (`Socket.IO`) with upload progress tracking and support for files up to **2 GB**.
- **Image Preview & Quick Copy:** Inline image previews with lightbox zoom, one-click download buttons, message dropdown actions (`Copy`, `Download`, `Delete`), and an option to convert long text snippets into downloadable `.txt` files.
- **Customizable Auto-Expiration (Max 24 Hours):** Choose message retention periods from **5 minutes** up to **24 hours**; expired messages and uploaded files are automatically purged from RAM and disk.
- **Focused Topics (Private Rooms):** Create topic-specific rooms where the creator becomes the admin, approve or decline join requests from other LAN devices, manage members, and configure room inactivity expiration.
- **Live Link Previews:** Automatically generates thumbnail cards for shared URLs (including YouTube videos and news articles) while typing, with an option to dismiss before sending.
- **Offline QR Code Sharing:** Built-in QR code generator for quick mobile access without needing internet connectivity.
- **Mobile-First Portrait UI & Adaptive Theme:** Centered portrait layout on desktop, full viewport on mobile, and automatic Light/Dark mode matching browser preferences (with manual toggle).

---

## Quick Start

### Option 1: Docker Compose (Recommended)

1. Download or copy [`docker-compose.yml`](docker-compose.yml) into a new folder on your host machine.
2. *(Optional)* Set `QR_URL` in `docker-compose.yml` to your host machine's LAN IP and port (e.g., `http://192.168.1.10:3000`) so the QR code points directly to the accessible network address.
3. Start the container:
   ```bash
   docker compose up -d

### Option 2: Docker CLI

docker run -d \
  --name localchat \
  --restart unless-stopped \
  -p 3000:80 \
  -e APP_TITLE="LocalChat" \
  -e APP_SUBTITLE="Local Network Communication" \
  -e QR_URL="[http://192.168.1.10:3000](http://192.168.1.10:3000)" \
  -v localchat_uploads:/app/uploads \
  stbdba/localchat:0.1.0
