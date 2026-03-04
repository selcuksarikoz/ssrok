# SSrok - Reverse Tunnel for VS Code

A VS Code extension that creates secure reverse tunnels to expose your local development server to the internet.

## What is ssrok?

ssrok is an **open-source self-hosted reverse tunnel proxy** with end-to-end encryption. Use this extension to expose local ports without installing any CLI tools.

- **Self-hosted** — Run your own server, own your data
- **Open source** — Fully transparent, audit the code
- **E2E encrypted** — Server cannot see your traffic (ChaCha20-Poly1305)
- **Ephemeral** — Auto-expiring tunnels for security

## Web Interface

Use ssrok without installing anything: **[https://kuulto.app/ssrok](https://kuulto.app/ssrok)**

## Features

- Auto-detect open ports (3000, 3001, 4000, 5000, 5173, 8000, 8080, 8888)
- Custom port input
- End-to-end encryption support
- Rate limiting configuration (0 = unlimited)
- Clickable public & magic URLs
- Built-in QR code generator
- One-click disconnect

## Usage

1. Press `Cmd+Shift+P` and type "SSrok: Start Tunnel"
2. Select or enter the port to tunnel
3. Click "Start Tunnel"
4. Copy the public/magic URL or scan the QR code to share

## Commands

- `ssrok.start` - Start a new tunnel
- `ssrok.stop` - Stop the current tunnel

## Configuration

- `ssrok.defaultPort` - Default port to tunnel (default: 3000)
- `ssrok.e2ee` - Enable E2EE by default (default: true)
- `ssrok.rateLimit` - Rate limit in requests per minute (default: 0 = unlimited)

## Self-Hosting

Since ssrok is open-source, you can run your own server:

```bash
git clone https://github.com/selcuksarikoz/ssrok.git
cd ssrok
make build-server
./ssrok-server  # listens on port 80 by default
```

The server requires no external dependencies. All tunnel state is stored in memory by default.

## Links

- **GitHub**: https://github.com/selcuksarikoz/ssrok
- **Web Interface**: https://kuulto.app/ssrok
