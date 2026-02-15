# AGENTS.md - Development Guidelines for ssrok

## Overview

Development standards and best practices for ssrok.

## Core Principles

### DRY (Don't Repeat Yourself)
- Extract reusable logic into functions/packages
- Single source of truth for all configuration
- Use `internal/utils/` for shared code

### SOLID Principles

**Single Responsibility**: One responsibility per function/file/package
**Open/Closed**: Extend via interfaces, don't modify existing code  
**Liskov Substitution**: Interface implementations must be interchangeable
**Interface Segregation**: Small, focused interfaces
**Dependency Inversion**: Depend on abstractions, use dependency injection

## Architecture

### Package Structure

```
cmd/
  client/          # CLI entry point
  server/          # Server entry point

internal/
  constants/       # Configuration constants
  security/        # Security implementations
  session/         # Session management
  tunnel/          # Tunnel logic
  utils/           # Shared utilities
```

### File Rules
- Max 300 lines per file
- One struct per file (unless tightly coupled)
- Define interfaces near usage
- `*_test.go` alongside source files

## Security Requirements

### Mandatory
- All input validated in `security/validator.go`
- Token auth for all endpoints
- Brute force protection (5 attempts = 15min block)
- Rate limiting per IP (default: 10 concurrent, 60 req/min)
- Audit logging for security events
- Secure headers (CSP, X-Frame-Options, HSTS)
- No sensitive data in logs
- Session timeout (1 hour)

### Checklist
- [ ] All endpoints authenticated
- [ ] Input validation
- [ ] Rate limiting enabled
- [ ] Audit logging
- [ ] Security headers
- [ ] No sensitive data in logs
- [ ] Session timeout
- [ ] Brute force protection

## Performance

### Rules
- Use `sync.Pool` for buffer reuse
- Buffer size: 128KB default
- TCP_NODELAY enabled
- Pre-allocate slices
- Zero-allocation hot paths

### Checklist
- [ ] Buffer pooling
- [ ] No allocations in loops
- [ ] Efficient data structures
- [ ] Proper goroutine coordination
- [ ] Resource cleanup with defer

## Code Standards

### Naming
- Packages: lowercase, single word (`security`, not `security_utils`)
- Types: PascalCase (`ConnectionLimiter`)
- Functions: CamelCase, verb-first (`ValidateToken`)
- Variables: CamelCase, meaningful (`conn`, not `c`)
- Constants: PascalCase exported, UPPER_SNAKE unexported

### Error Handling
```go
// Good
if err := doSomething(); err != nil {
    return fmt.Errorf("context: %w", err)
}

// Bad
doSomething() // ignoring error
```

### Logging
- Structured JSON format
- No sensitive data (passwords, tokens)
- Include session/request IDs

## Testing

- Min 80% coverage
- 100% for security/auth/tunnel
- Unit + integration tests
- Security tests (bypass, injection)

## Configuration

- All config via environment variables
- Use constants from `internal/constants/`
- Never hardcode URLs, ports, secrets

```go
host := utils.GetEnv("SSROK_HOST", constants.DefaultHost)
```

## Anti-Patterns

1. No global state
2. No `init()` with I/O
3. No import cycles
4. No panics in production
5. No hardcoded values
6. No TODO without GitHub issue
7. No commented-out code
8. No magic numbers

## Build

```bash
make build          # Build binaries
make test           # Run tests
make release        # Release builds
```

## Release Process

1. Update version in Makefile
2. Run `make release`
3. Generate checksums
4. Update Homebrew formula
5. Create GitHub release
