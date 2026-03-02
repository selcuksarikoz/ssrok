# ssrok

**Secure, ephemeral reverse proxy tunnels for developers.**

Expose your local development server to the internet with a secure, time-limited URL, or **securely share your screen** straight from the terminal. Perfect for testing webhooks, sharing work-in-progress with clients, quick demos, or **developing APIs**. You can send requests to your local API endpoints directly using **curl**, **Postman**, or any other HTTP client via the public URL.

> **Note:** A free public instance is available at [ssrok.onrender.com](https://ssrok.onrender.com). Please be aware that this runs on a free tier infrastructure, which may experience cold starts or resource limitations.

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Why ssrok?

- **Instant** — Get a public URL in seconds, not minutes
- **End-to-End Encrypted** — Server cannot see your traffic (ChaCha20-Poly1305)
- **Secure** — Token authentication + optional password protection
- **Ephemeral** — URLs auto-expire (default: 1 hour)
- **Fast** — 128KB buffers, yamux multiplexing, zero-copy transfers
- **Rate Limited** — Built-in DDoS prevention per session
- **Quick Config** — Interactive prompts for password, rate limit, duration
- **API Ready** — Programmatic tunnel creation via REST API

## Quick Start

```bash
# Share your screen securely (requires auth)
ssrok screen

# Screen share with custom quality (1-100) and framerate
ssrok screen -fps 30 -quality 90

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
   dashboard:  http://localhost:31331
   local:      http://localhost:3000
   expires:    60 min
```

- **Magic URL** — Share with anyone, no password needed
- **Public URL** — Password-protected, for sensitive demos
- **Dashboard** — View real-time requests at `http://localhost:31331`

## Installation

### Quick Install (Recommended)

**macOS:**

```bash
sudo curl -sL https://github.com/selcuksarikoz/ssrok/releases/latest/download/ssrok-darwin-arm64 -o /usr/local/bin/ssrok
sudo chmod +x /usr/local/bin/ssrok
```

### via Homebrew (Recommended)

```bash
brew tap selcuksarikoz/ssrok https://github.com/selcuksarikoz/ssrok
brew install ssrok
```

**Linux:**

```bash
sudo curl -sL https://github.com/selcuksarikoz/ssrok/releases/latest/download/ssrok-linux-amd64 -o /usr/local/bin/ssrok
sudo chmod +x /usr/local/bin/ssrok
```

**Windows:**

```powershell
# Run as Administrator in PowerShell
Invoke-WebRequest -Uri "https://github.com/selcuksarikoz/ssrok/releases/latest/download/ssrok-windows-amd64.exe" -OutFile "C:\Windows\ssrok.exe"
```

Or download manually from the [releases page](https://github.com/selcuksarikoz/ssrok/releases).

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

**macOS / Linux:**

```bash
sudo mv ssrok /usr/local/bin/
```

**Windows:**

Move the binary to a folder in your PATH, for example:

```powershell
# Option 1: System-wide (requires Administrator)
Move-Item ssrok.exe C:\Windows\System32\ssrok.exe

# Option 2: User PATH (recommended)
# Create a folder (e.g., C:\Users\YourUser\bin) and add it to your PATH:
# Then move the file there
Move-Item ssrok.exe C:\Users\YourUser\bin\ssrok.exe
```

To add a folder to your PATH on Windows:

```powershell
# Open PowerShell and run:
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Users\YourUser\bin", "User")
```

Alternatively, you can use the make command to install both (macOS / Linux only):

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

| Feature               | Description                                  |
| --------------------- | -------------------------------------------- |
| ⚡ **Fast**           | 128KB buffers, yamux multiplexing            |
| 🔒 **E2E Encryption** | ChaCha20-Poly1305, server cannot see traffic |
| 📺 **Screen Share**   | Secure, platform-independent screen sharing  |
| 🔐 **Secure**         | Token auth, optional password                |
| 🎫 **Magic Links**    | URLs with embedded tokens                    |
| ⏱️ **Ephemeral**      | Auto-expire after 1 hour                     |
| 🚦 **Rate Limiting**  | Per-IP, per-session throttling               |
| 📊 **Dashboard**      | Real-time request inspector                  |
| 📝 **Session Logs**   | JSON logs for each tunnel                    |
| 💾 **Redis**          | Optional persistence                         |

## Dashboard

When you start a tunnel, a local dashboard is automatically available at `http://localhost:31331`. This real-time request inspector shows:

- **Live Requests** — All HTTP requests passing through the tunnel
- **Method & Path** — GET, POST, PUT, DELETE with full URLs
- **Status Codes** — Color-coded responses (green=success, red=error, yellow=redirect)
- **Response Time** — Request duration in milliseconds
- **Request Details** — Click any request to see headers and response info

```
   GET  /api/users        200  12ms
   POST /api/login        401  45ms
   GET  /static/app.js   200  8ms
```

The dashboard helps you debug API responses, inspect webhook payloads, and monitor traffic in real-time.

> **Note:** The dashboard runs locally on your machine and is not accessible from the internet. It shows requests as they pass through your local client before encryption.

### Troubleshooting

**macOS "cannot capture display" error**

If you are using macOS and see the `cannot capture display` error when running `ssrok screen`, you need to grant **Screen Recording** permissions to your terminal:

1. Open **System Settings** -> **Privacy & Security** -> **Screen Recording**.
2. Find your terminal application (e.g., Terminal, iTerm2, VSCode, Cursor) in the list and enable the switch.
3. If it's not in the list, click the `+` button at the bottom and add your terminal app.
4. **Quit & Reopen** your terminal for the changes to take effect.

## Security & Limitations

### End-to-End Encryption

ssrok uses **ChaCha20-Poly1305** authenticated encryption with **X25519** key exchange. This means:

- **Server cannot see your traffic** — All data between your local server and visitors is encrypted on your client machine before being sent through the server
- **Forward secrecy** — New encryption keys are generated for each tunnel session
- **Tamper proof** — Any modification to encrypted data is detected and rejected

```
Visitor → [HTTPS] → ssrok Server → [E2E Encrypted] → Your Local Server
                                    ↑ Server cannot decrypt this
```

### Security Features

- **Token Authentication**: Required for all connections to prevent unauthorized usage.
- **Password Protection**: Optional SHA256 password protection for your public URLs.
- **Rate Limiting**: Built-in DDoS prevention (default: unlimited), fully configurable.
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
┌─────────────┐     WebSocket (TLS)      ┌─────────────┐      HTTPS      ┌─────────────┐
│   Client    │ ◄─────────────────────► │   Server    │ ◄────────────► │  Visitor    │
│ (ssrok CLI) │    E2E Encrypted        │  (relay)    │   Token/Pass   │ (Browser)   │
│  (local)    │   (ChaCha20-Poly1305)   │             │                │             │
└──────┬──────┘                         └─────────────┘                └─────────────┘
       │
       └──── localhost:3000
```

- **Client** runs on your machine, encrypts all traffic before sending
- **Server** acts as a relay, only sees encrypted data
- **Visitor** connects via HTTPS, their requests are decrypted by your client

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
    "rate_limit": 0,
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

## Acknowledgements & Open Source Packages

ssrok is built on top of these amazing open-source packages:

- [kbinani/screenshot](https://github.com/kbinani/screenshot) - Cross-platform screen capture
- [google/uuid](https://github.com/google/uuid) - UUID generation
- [gorilla/websocket](https://github.com/gorilla/websocket) - WebSocket implementation
- [hashicorp/yamux](https://github.com/hashicorp/yamux) - Connection multiplexing
- [charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea) & [lipgloss](https://github.com/charmbracelet/lipgloss) - TUI frameworks

## License

MIT
