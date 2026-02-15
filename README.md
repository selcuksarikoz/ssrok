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
git clone https://github.com/ssrok/ssrok.git
cd ssrok
make build
```

## Usage

### Client

```bash
ssrok 3000
```

Interactive prompts:
1. **Server Configuration** - Use HTTPS? [y/N]
2. **TLS Certificate** - Skip verification? (for local self-signed certs)
3. **Password** (optional) - Additional protection layer
4. **Rate Limit** (default: 60 req/min) - Per-IP throttling

### Server

```bash
# HTTP mode (local development)
ssrok-server

# HTTPS mode (requires TLS certificates)
# Certificates: certs/server.crt, certs/server.key
ssrok-server

# With environment variables
PORT=8080 SSROK_HOST=tunnel.example.com ssrok-server
```

**Environment Variables:**
- `PORT` - Server port (default: 8080)
- `SSROK_HOST` - Public host (without protocol)
- `SSROK_CERT_FILE` - TLS certificate path (optional)
- `SSROK_KEY_FILE` - TLS key path (optional)

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
- **Rate Limiting**: Per-IP request throttling (default: 60 req/min)
- **Connection Limits**: Max 10 concurrent connections per IP
- **Brute Force Protection**: 5 failed attempts = 15min ban
- **Auto Cleanup**: Sessions destroyed after 1 hour
- **No Persistence**: All data in memory only
- **Audit Logging**: Security events logged to JSON files

## Logging

Session logs stored per-tunnel:

- **macOS**: `~/Library/Logs/ssrok/{uuid}.log`
- **Linux**: `~/.local/share/ssrok/logs/{uuid}.log`
- **Windows**: `%USERPROFILE%\AppData\Local\ssrok\logs\{uuid}.log`

Audit logs:

- **macOS**: `~/Library/Logs/ssrok/audit/audit-YYYY-MM-DD.log`
- **Linux**: `~/.local/share/ssrok/audit/audit-YYYY-MM-DD.log`

JSON format:
```json
{"timestamp":"2026-02-15T12:00:00Z","direction":"server->client","type":"data","size":1024,"remote_addr":"...","local_port":3000}
{"timestamp":"2026-02-15T12:00:01Z","event_type":"auth_failure","ip":"...","severity":"warning","details":"Invalid password"}
```

## Deployment

### Local Development

```bash
# Generate self-signed certificates
./scripts/generate-certs.sh

# Run server
./ssrok-server

# Run client
./ssrok 3000
# Use HTTPS? [y/N]: y
# Skip verification? [y/N]: y
```

### Production (Render.com)

1. Deploy server with `ssrok-server` binary
2. Set environment variables:
   - `PORT` - Required by Render
   - `SSROK_HOST` - Your Render domain
3. SSL is handled by Render's reverse proxy

### Custom TLS

```bash
# Server with TLS certificates
SSROK_CERT_FILE=/path/to/cert.crt SSROK_KEY_FILE=/path/to/key.key ssrok-server
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/register` | POST | - | Register new tunnel |
| `/ws/{uuid}?token=` | WS | Token | WebSocket tunnel |
| `/{uuid}?token=` | GET | Token+Pass | Public access |

## Development

```bash
# Build
make build        # Both binaries
make build-client # Client only
make build-server # Server only

# Test
go test ./...

# Release
make release
```

## License

MIT
