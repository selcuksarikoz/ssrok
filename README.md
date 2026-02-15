# ssrok

**Secure, ephemeral reverse proxy tunnels for developers.**

Expose your local development server to the internet with a secure, time-limited URL. Perfect for testing webhooks, sharing work-in-progress with clients, quick demos, or **developing APIs**. You can send requests to your local API endpoints directly using **curl**, **Postman**, or any other HTTP client via the public URL.

> **Note:** A free public instance is available at [ssrok.onrender.com](https://ssrok.onrender.com). Please be aware that this runs on a free tier infrastructure, which may experience cold starts or resource limitations.

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

### Quick Install (Recommended)

```bash
curl -sL https://github.com/selcuksarikoz/ssrok/releases/latest/download/ssrok-darwin-arm64 -o /usr/local/bin/ssrok
chmod +x /usr/local/bin/ssrok
```

### via Homebrew (Recommended)

```bash
brew tap selcuksarikoz/ssrok https://github.com/selcuksarikoz/ssrok
brew install ssrok
```

### Build from Source

You can build the client and server binaries manually using the provided Makefile.

```bash
git clone https://github.com/selcuksarikoz/ssrok.git
cd ssrok

# Build both client and server
make build

# Build individually
make build-client   # output: ./ssrok
make build-server   # output: ./ssrok-server
```

### Binary Installation

After building, you can install the binaries to your system path to use them globally.

**Client:**

```bash
sudo mv ssrok /usr/local/bin/
```

**Server:**

```bash
sudo mv ssrok-server /usr/local/bin/
```

Alternatively, you can use the make command to install both:

```bash
sudo make install
```

## Self-Hosting

You have the freedom to host your own `ssrok` server for complete control over your data and infrastructure.

1.  **Build the Server**: Run `make build-server` to generate the `ssrok-server` binary.
2.  **Deploy**: Upload the `ssrok-server` binary to your VPS or cloud server.
3.  **Run**: Execute the binary on your server.

```bash
# Example run
./ssrok-server
```

Make sure to configure the Environment Variables (see below) to match your domain and requirement.

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

## Security & Limitations

### Security Features

- **Token Authentication**: Required for all connections to prevent unauthorized usage.
- **Password Protection**: Optional SHA256 password protection for your public URLs.
- **Rate Limiting**: Built-in DDoS prevention (default: 60 req/min/IP), fully configurable.
- **Brute Force Protection**: IP banning after 5 failed authentication attempts (15 min ban).
- **Audit Logging**: Comprehensive logs for all security-critical events.

### Developer constraints

To ensure the stability and security of the shared tunnel infrastructure, the following limitations apply:

- **100MB Body Limit**: The maximum allowed request body size (e.g., file uploads) is **100MB**.
- **Header Filtering**: Request headers (including `Cookie` and `Authorization`) are forwarded to your local app. However, the following **Response Headers** are stripped from the response for security reasons:
  - `Set-Cookie` — _Cookie-based sessions will not persist immediately on the tunnel domain. Use **JWT/Bearer tokens** for API authentication._
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` & `X-Xss-Protection`

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

| Field        | Type   | Required | Description                       |
| ------------ | ------ | -------- | --------------------------------- |
| `port`       | int    | Yes      | Local port to tunnel              |
| `password`   | string | No       | Optional password protection      |
| `rate_limit` | int    | No       | Requests per minute (0=unlimited) |
| `use_tls`    | bool   | No       | Enable TLS for local connection   |
| `expires_in` | string | No       | Duration (e.g. "1h", "30m")       |

## Development

```bash
make build          # Build binaries
make dev-server     # Run server locally
make test           # Run tests
make release        # Release builds
```

## License

MIT
