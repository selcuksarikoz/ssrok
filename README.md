# ssrok

**Secure, ephemeral reverse proxy tunnels for developers.**

Expose your local development server to the internet with a secure, time-limited URL. Perfect for testing webhooks, sharing work-in-progress with clients, or quick demos.

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Why ssrok?

- **Instant** — Get a public URL in seconds, not minutes
- **Secure** — Token authentication + optional password protection
- **Ephemeral** — URLs auto-expire (default: 1 hour)
- **Fast** — 128KB buffers, yamux multiplexing, zero-copy transfers
- **Rate Limited** — Built-in DDoS prevention per session
- **Quick Config** — Interactive prompts for password, rate limit, duration
- **API Ready** — Programmatic tunnel creation via REST API

## Quick Start

```bash
# Expose localhost:3000
ssrok 3000

# Or with custom host:port
ssrok localhost:8080
ssrok 192.168.1.5:8000
```

That's it. You'll get:

```
   magic url:  https://your-server.app/abc123?token=xyz
   public url: https://your-server.app/abc123
   local:      http://localhost:3000
   expires:    60 min
```

- **Magic URL** — Share with anyone, no password needed
- **Public URL** — Password-protected, for sensitive demos

## Installation

### macOS

```bash
# Add the tap (requires GitHub repository: selcuksarikoz/homebrew-tap)
brew tap selcuksarikoz/ssrok

# Install ssrok
brew install ssrok
```

Or install directly:

```bash
brew install selcuksarikoz/ssrok/ssrok
```

### Build from Source

```bash
git clone https://github.com/selcuksarikoz/ssrok.git
cd ssrok
make build
```

## Features

| Feature              | Description                       |
| -------------------- | --------------------------------- |
| ⚡ **Fast**          | 128KB buffers, yamux multiplexing |
| 🔒 **Secure**        | Token auth, optional password     |
| 🎫 **Magic Links**   | URLs with embedded tokens         |
| ⏱️ **Ephemeral**     | Auto-expire after 1 hour          |
| 🚦 **Rate Limiting** | Per-IP, per-session throttling    |
| 📝 **Session Logs**  | JSON logs for each tunnel         |
| 💾 **Redis**         | Optional persistence              |

## Security

- Token authentication required for all connections
- Optional SHA256 password protection
- Rate limiting: 60 req/min per IP (configurable)
- Max 10 concurrent connections per IP
- Brute force protection: 5 failed attempts → 15 min ban
- Auto-cleanup: sessions destroyed after expiry
- Audit logging for security events

## Architecture

```
┌─────────────┐     WebSocket/yamux     ┌─────────────┐      HTTP       ┌─────────────┐
│   Client    │ ◄─────────────────────► │   Server    │ ◄────────────► │  Visitor    │
│ (ssrok CLI) │    Token Required       │  (:80)     │   Token/Pass   │ (Browser)   │
└──────┬──────┘                         └─────────────┘                └─────────────┘
       │
       └──── localhost:3000
```

## Environment Variables

| Variable           | Default     | Description           |
| ------------------ | ----------- | --------------------- |
| `PORT`             | `80`        | Server listen port    |
| `SSROK_SERVER`     | `localhost` | Public hostname       |
| `SSROK_ENABLE_TLS` | `false`     | Enable built-in TLS   |
| `REDIS_HOST`       | (none)      | Redis host (optional) |
| `REDIS_PORT`       | `6379`      | Redis port            |

## API (Programmatic Usage)

You can create tunnels programmatically via the REST API:

```bash
# Register a tunnel
curl -X POST https://your-server.com/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "port": 3000,
    "password": "optional",
    "rate_limit": 60,
    "use_tls": false,
    "expires_in": "1h"
  }'
```

**Response:**
```json
{
  "uuid": "abc123",
  "url": "https://your-server.com/abc123",
  "token": "xyz789",
  "expires_in": "1h0m0s"
}
```

**Connect via WebSocket:**
```bash
wss://your-server.com/ws/abc123?token=xyz789
```

### Request Fields

| Field        | Type    | Required | Description                    |
| ------------ | ------- | -------- | ------------------------------ |
| `port`       | int     | Yes      | Local port to tunnel          |
| `password`   | string  | No       | Optional password protection  |
| `rate_limit` | int     | No       | Requests per minute (0=unlimited) |
| `use_tls`    | bool    | No       | Enable TLS for local connection |
| `expires_in` | string  | No       | Duration (e.g. "1h", "30m")   |

## Development

```bash
make build          # Build binaries
make dev-server     # Run server locally
make test           # Run tests
make release        # Release builds
```

## License

MIT
