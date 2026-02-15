# homebrew-tap

**ssrok** — Secure, ephemeral reverse proxy tunnel for developers.

> ⚠️ **Note**: This tap must be published as a GitHub repository named `homebrew-tap` under your username.
> Example: `https://github.com/selcuksarikoz/homebrew-tap`

## Installation

Once the tap is published, run:

```bash
# Add the tap
brew tap selcuksarikoz/ssrok

# Install ssrok
brew install ssrok
```

Or install directly without tapping:

```bash
brew install selcuksarikoz/ssrok/ssrok
```

## Usage

```bash
# Expose localhost:3000
ssrok 3000

# Expose custom host:port
ssrok localhost:8080
```

## Update

```bash
brew update && brew upgrade ssrok
```

Or use the built-in update command:

```bash
ssrok --update
```

## Uninstall

```bash
brew uninstall ssrok
```

## Why ssrok?

- ⚡ **Instant** — Get a public URL in seconds
- 🔒 **Secure** — Token auth + optional password
- ⏱️ **Ephemeral** — Auto-expire after 1 hour
- 🚦 **Rate Limited** — Built-in DDoS protection
- ⚙️ **Quick Config** — Interactive prompts for customization
- 🔌 **API Ready** — Programmatic tunnel creation

## Learn More

- [GitHub](https://github.com/selcuksarikoz/ssrok)
- [Documentation](https://github.com/selcuksarikoz/ssrok#readme)
