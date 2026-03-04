# SSrok - VS Code Extension

Instantly expose your local development server to the internet with a single click. Perfect for testing webhooks, sharing work-in-progress with teammates, or debugging on mobile devices — all without leaving VS Code or installing any CLI tools.

```
Your Localhost → Secure Public URL (seconds)
localhost:3000 → https://xxxx.ssrok.app
```

## Features

- **No Installation Required**: Use without installing ssrok CLI application
- **Auto Port Detection**: Automatically detects ports 3000, 3001, 4000, 5000, 5173, 8000, 8080, 8888
- **End-to-End Encryption**: Secure communication with ChaCha20-Poly1305
- **QR Code**: Quick access from mobile devices with QR code support
- **Rate Limiting**: Configurable requests per minute limit
- **One-Click Disconnect**: Instantly terminate the tunnel

## Usage

### 1. Start from Command Palette

Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Windows/Linux) → type "SSrok: Start Tunnel"

### 2. Port Selection

In the opened panel:
- Select from automatically detected ports, or
- Choose "Custom..." to enter a different port

### 3. Tunnel Configuration

- **Password** (optional): Access password for the tunnel
- **Rate Limit**: Maximum requests per minute (0 = unlimited)
- **E2EE**: End-to-end encryption on/off

### 4. Connect

Click "Start Tunnel" button. Public URL and Magic URL will be generated.

## Alternative Usage Methods

### With ssrok CLI

If you prefer using ssrok from terminal:

```bash
ssrok 3000
```

To run on your own server:

```bash
git clone https://github.com/selcuksarikoz/ssrok.git
cd ssrok
make build-server
./ssrok-server
```

## Configuration

Customize via VS Code settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `ssrok.defaultPort` | 3000 | Default port to tunnel |
| `ssrok.e2ee` | true | Default E2EE state |
| `ssrok.rateLimit` | 0 | Default rate limit (0 = unlimited) |

## Commands

- `SSrok: Start Tunnel` - Start a new tunnel
- `SSrok: Stop Tunnel` - Stop active tunnel
- `SSrok: Show Panel` - Show tunnel panel

## Security

- All traffic is end-to-end encrypted (ChaCha20-Poly1305)
- Optional password protection
- Automatic expiration (ephemeral tunnels)

## Links

- **GitHub**: https://github.com/selcuksarikoz/ssrok
- **Web Interface**: https://kuulto.app/ssrok

## License

MIT
