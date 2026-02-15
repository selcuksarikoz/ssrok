# ssrok

Secure, ephemeral reverse proxy tunnels. Expose your local dev server to the internet.

## Features

- ⚡ **Fast** — 128KB buffers, yamux multiplexing, zero-allocation transfers
- 🔒 **Secure** — Token auth, optional password, brute force protection
- 🎫 **Magic Links** — Share secure URLs with embedded tokens
- ⏱️ **Ephemeral** — Sessions auto-expire after 1 hour
- 🚦 **Rate Limiting** — Per-IP, per-session throttling
- 📝 **Logging** — Per-session JSON logs

## Installation

### macOS (Homebrew)

```bash
brew tap selcuksarikoz/ssrok
brew install ssrok
```

### Linux

```bash
# AMD64
curl -L https://github.com/selcuksarikoz/ssrok/releases/latest/download/ssrok-linux-amd64 -o ssrok
chmod +x ssrok
sudo mv ssrok /usr/local/bin/
```

### Windows

Download `ssrok-windows-amd64.exe` from [Releases](https://github.com/selcuksarikoz/ssrok/releases/latest) and add to your PATH.

```powershell
# PowerShell
Invoke-WebRequest -Uri "https://github.com/selcuksarikoz/ssrok/releases/latest/download/ssrok-windows-amd64.exe" -OutFile "ssrok.exe"
Move-Item ssrok.exe C:\Windows\System32\
```

### Build from Source

```bash
git clone https://github.com/selcuksarikoz/ssrok.git
cd ssrok
make build
```

## Quick Start

### 1. Start the Server

```bash
go run cmd/server/main.go
```

### 2. Start the Client

```bash
# Expose localhost:3000 (default)
ssrok 3000

# Expose specific host:port
ssrok localhost:8080

# Expose external IP (e.g. device on local network)
ssrok 192.168.1.5:8000
```

You'll get a Magic URL and a Raw URL:

```
╔══════════════════════════════════════════════════════════╗
║                    🚀 Tunnel Active                      ║
╚══════════════════════════════════════════════════════════╝

   Magic URL: http://localhost/UUID?token=TOKEN
   Raw URL:   http://localhost/UUID

   Local:     http://localhost:3000
   Expires:   05:30 (1 hour)
```

- **Magic URL** — Direct access, no password required
- **Raw URL** — Requires password (if set)

## Configuration

All configuration is done via `.env` file or environment variables.

```bash
cp .env.example .env
```

| Variable           | Default            | Description          |
| ------------------ | ------------------ | -------------------- |
| `PORT`             | `80`               | Server listen port   |
| `SSROK_HOST`       | `localhost`        | Public hostname      |
| `SSROK_ENABLE_TLS` | `false`            | Enable built-in TLS  |
| `SSROK_CERT_FILE`  | `certs/server.crt` | TLS certificate path |
| `SSROK_KEY_FILE`   | `certs/server.key` | TLS key path         |

## Production Deployment

### 1. Environment Configuration

For production, start by copying the example production configuration:

```bash
cp env.prod.example .env
```

Edit `.env` to set your production values:

- `SSROK_DOMAIN`: Set your public domain
- `SSROK_ENABLE_TLS`: Enable if handling SSL directly (otherwise let Nginx/Cloudflare handle headers)

**Note:**

- **Server**: Always reads configuration from `.env` in the working directory.
- **Development**: You can test production settings locally by setting `SSROK_CONFIG_FILE`:
  ```bash
  SSROK_CONFIG_FILE=.env.prod make dev-server
  ```

### 2. Helper Scripts

The project includes helper scripts for common tasks, integrated into the Makefile:

```bash
# Generate self-signed certificates for local HTTPS testing
make gen-certs

# Run the server locally (uses dev config by default)
make dev-server

# Build the client using production settings
make build-script
```

## Architecture

```
┌─────────────┐     WebSocket/yamux     ┌─────────────┐      HTTP       ┌─────────────┐
│   Client    │ ◄─────────────────────► │   Server    │ ◄────────────► │  Visitor    │
│ (ssrok CLI) │    Token Required       │  (:8080)    │   Token/Pass   │ (Browser)   │
└──────┬──────┘                         └─────────────┘                └─────────────┘
       │
       └──── localhost:3000
```

## Security

- **Token Auth** — All connections require valid tokens
- **Password** — Optional SHA256 password layer
- **Secure Cookies** — HttpOnly, Secure, SameSiteStrict
- **Rate Limiting** — Per-IP per-session (default: 60 req/min)
- **Connection Limits** — Max 10 concurrent per IP
- **Brute Force** — 5 failed attempts → 15 min ban
- **Auto Cleanup** — Sessions destroyed after 1 hour
- **In-Memory** — No data persistence, no database
- **Audit Log** — Security events logged to JSON

## Logging

Session logs per-tunnel:

| OS      | Path                                                |
| ------- | --------------------------------------------------- |
| macOS   | `~/Library/Logs/ssrok/{uuid}.log`                   |
| Linux   | `~/.local/share/ssrok/logs/{uuid}.log`              |
| Windows | `%USERPROFILE%\AppData\Local\ssrok\logs\{uuid}.log` |

## API

| Endpoint            | Method | Description      |
| ------------------- | ------ | ---------------- |
| `/`                 | GET    | Landing page     |
| `/api/register`     | POST   | Register tunnel  |
| `/ws/{uuid}?token=` | WS     | WebSocket tunnel |
| `/{uuid}?token=`    | GET    | Access tunnel    |

## Development

```bash
make build          # Build binaries
make build-client   # Client only
make build-server   # Server only
go test ./...       # Run tests
make release        # Release builds
```

## License

MIT
