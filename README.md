# ssrok

Blazing fast secure reverse proxy tunnel (ngrok alternative) built in Go.

## Features

- ⚡ **Blazing Fast** - 128KB buffers, optimized yamux, zero-allocation transfers
- 🔒 **Token Security** - All connections require valid tokens (WebSocket + HTTP)
- 🔐 **Optional Password** - Additional password protection layer
- 🎫 **Magic Links** - Share access via secure token URLs
- 📝 **Session Logging** - Per-session JSON logs with traffic stats
- ⏱️ **Auto Expiry** - Sessions expire after 1 hour
- 🚦 **Rate Limiting** - Per-IP rate limiting per tunnel
- 🔄 **WebSocket + Yamux** - Multiplexed connections with 1MB window

## Installation

### macOS / Linux (Homebrew)

```bash
brew tap ssrok/tap
brew install ssrok
```

### Binary Download

Download latest release from [Releases](https://github.com/ssrok/ssrok/releases):

```bash
# macOS ARM64 (Apple Silicon)
curl -L https://github.com/ssrok/ssrok/releases/latest/download/ssrok-darwin-arm64 -o ssrok
chmod +x ssrok
sudo mv ssrok /usr/local/bin/

# macOS AMD64 (Intel)
curl -L https://github.com/ssrok/ssrok/releases/latest/download/ssrok-darwin-amd64 -o ssrok
chmod +x ssrok
sudo mv ssrok /usr/local/bin/

# Linux AMD64
curl -L https://github.com/ssrok/ssrok/releases/latest/download/ssrok-linux-amd64 -o ssrok
chmod +x ssrok
sudo mv ssrok /usr/local/bin/
```

### Build from Source

```bash
go install github.com/ssrok/ssrok/cmd/client@latest
```

## Usage

### Client

```bash
# Connect local port 3000 to ssrok server
ssrok 3000

# With custom server
SSROK_SERVER=https://tunnel.example.com ssrok 3000
```

Interactive prompts:
- **Password** (optional): Leave empty for token-only access, or set for additional protection
- **Rate Limit** (default: 60): Requests per minute per IP (0 = unlimited)

Output:
```
╔══════════════════════════════════════════════════════════╗
║                    🚀 Tunnel Active                      ║
╠══════════════════════════════════════════════════════════╣
║  Magic URL: https://tunnel.example.com/550e8400-e29b...?token=... ║
║  Raw URL:   https://tunnel.example.com/550e8400-e29b...           ║
║  Local:     http://localhost:3000                                  ║
║  Expires:   14:32:15 (1 hour)                                      ║
╚══════════════════════════════════════════════════════════╝
📝 Logs: ~/Library/Logs/ssrok/550e8400-e29b-41d4-a716-446655440000.log
```

### Server

```bash
# Quick start
ssrok-server

# With custom settings
PORT=9000 SSROK_HOST=https://tunnel.example.com ssrok-server
```

Environment variables:
- `PORT` - Server port (default: 8080)
- `SSROK_HOST` - Public host URL (default: http://localhost:8080)

## Architecture

```
┌─────────────┐      WebSocket      ┌─────────────┐      HTTP      ┌─────────────┐
│   Client    │ ◄──────────────────► │   Server    │ ◄────────────► │   Visitor   │
│ (ssrok CLI) │   (Token Required)  │  (Public)   │   (Token +    │  (Browser)  │
└─────────────┘                     └─────────────┘   Password)    └─────────────┘
       │                                   │
       └──── localhost:3000                └──── https://host/{uuid}?token=...
```

## Performance

- **Buffer Size**: 128KB (32x vs standard 4KB)
- **Copy Buffer**: 256KB with sync.Pool reuse
- **Yamux Window**: 1MB stream window
- **TCP_NODELAY**: Enabled for low latency
- **Zero-Allocation**: Buffer pooling minimizes GC

Expected throughput: 500MB/s+ on gigabit networks

## Security

- **Token Authentication**: All connections (WebSocket & HTTP) require valid tokens
- **Password Layer**: Optional additional SHA256 password protection
- **Secure Cookies**: HttpOnly, Secure, SameSiteStrict
- **Rate Limiting**: Per-IP request throttling
- **Auto Cleanup**: Sessions destroyed after 1 hour
- **No Persistence**: All data in memory only

## Logging

Session logs stored per-tunnel:

- **macOS**: `~/Library/Logs/ssrok/{uuid}.log`
- **Linux**: `~/.local/share/ssrok/logs/{uuid}.log`
- **Windows**: `%USERPROFILE%\AppData\Local\ssrok\logs\{uuid}.log`

JSON format:
```json
{"timestamp":"2026-02-15T12:00:00Z","direction":"server->client","type":"data","size":1024,"remote_addr":"...","local_port":3000}
{"timestamp":"2026-02-15T12:00:01Z","direction":"client","type":"event","message":"Tunnel established","local_port":3000}
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/register` | POST | - | Register new tunnel |
| `/ws/{uuid}?token=` | WS | Token | WebSocket tunnel |
| `/{uuid}?token=` | GET | Token+Pass | Public access |

## Development

```bash
# Clone
git clone https://github.com/ssrok/ssrok.git
cd ssrok

# Build
make build        # Build both binaries
make build-client # Build client only
make build-server # Build server only

# Run locally
go run ./cmd/server    # Server on :8080
go run ./cmd/client 3000  # Client connecting to localhost:3000

# Test
go test ./...
```

## License

MIT
