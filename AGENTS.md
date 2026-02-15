# AGENTS.md - Development Guidelines for ssrok

## Overview

This document defines the development standards, architectural principles, and best practices for the ssrok project. All code contributions must adhere to these guidelines.

## Core Principles

### 1. DRY (Don't Repeat Yourself)
- **No code duplication**: Extract reusable logic into functions, types, or packages
- **Single source of truth**: Constants, configuration, and business logic must be defined once
- **Shared utilities**: Use `internal/utils/` for cross-cutting concerns
- **Template methods**: Use interfaces and composition for similar behaviors

### 2. SOLID Principles

#### Single Responsibility Principle (SRP)
- **One reason to change**: Each function, type, and file should have only one responsibility
- **Package cohesion**: Group related functionality into focused packages:
  - `internal/security/` - All security-related code
  - `internal/tunnel/` - Tunnel connection management
  - `internal/session/` - Session storage and management
- **Function size**: Keep functions under 50 lines; extract helper functions

#### Open/Closed Principle (OCP)
- **Open for extension**: Use interfaces to allow new implementations
- **Closed for modification**: Extend behavior through composition, not modification
- **Example**: New rate limiters should implement an interface, not modify existing code

#### Liskov Substitution Principle (LSP)
- **Substitutability**: Interface implementations must be fully interchangeable
- **No breaking changes**: Subtypes must not strengthen preconditions or weaken postconditions

#### Interface Segregation Principle (ISP)
- **Small interfaces**: Prefer many small interfaces over few large ones
- **Client-specific**: Interfaces should only expose what clients need
- **Example**: Separate `Logger` from `AuditLogger` interfaces

#### Dependency Inversion Principle (DIP)
- **Depend on abstractions**: Use interfaces, not concrete types
- **Dependency injection**: Pass dependencies through constructors or parameters
- **No hardcoded dependencies**: All external dependencies must be injectable

## Architecture Guidelines

### Package Structure

```
cmd/
  client/          # Client CLI entry point
  server/          # Server CLI entry point

internal/
  constants/       # Configuration constants ONLY
  protocol/        # Request/response types
  security/        # Security implementations
    ratelimiter.go
    validator.go
    audit.go
    headers.go
  session/         # Session management
  tunnel/          # Tunnel connection logic
  logger/          # Logging infrastructure
  utils/           # Shared utilities
```

### File Organization Rules

1. **Max 300 lines per file**: Split files that exceed this limit
2. **One struct per file**: Unless tightly coupled (e.g., config + options)
3. **Interface segregation**: Define interfaces close to their usage, not in a central file
4. **Test files**: Always create `*_test.go` files alongside source files

### Import Organization

```go
import (
    // Standard library (alphabetical)
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    
    // Third-party (alphabetical)
    "github.com/gorilla/websocket"
    
    // Internal packages (alphabetical)
    "ssrok/internal/constants"
    "ssrok/internal/security"
)
```

## Security Requirements

### Mandatory Security Measures

1. **Input Validation**
   - All external input must be validated in `internal/security/validator.go`
   - UUID format validation
   - Token format validation
   - Path traversal prevention
   - SQL/NoSQL injection prevention (sanitize all inputs)

2. **Authentication & Authorization**
   - Token-based auth for all endpoints
   - Brute force protection (5 attempts = 15min block)
   - Session expiration (1 hour max)
   - Secure cookie attributes (HttpOnly, Secure, SameSite)

3. **Rate Limiting**
   - Per-IP connection limits (default: 10 concurrent)
   - Per-tunnel request rate limits (default: 60 req/min)
   - Configurable per session

4. **Audit Logging**
   - All authentication failures logged
   - Rate limit violations logged
   - Security events in JSON format
   - Separate audit log directory

5. **Transport Security**
   - TLS for production deployments
   - WebSocket protocol matching (ws:// for HTTP, wss:// for HTTPS)
   - No hardcoded credentials or keys

### Security Checklist

- [ ] All endpoints require authentication (no public endpoints except health checks)
- [ ] Input validation on all user-provided data
- [ ] Rate limiting enabled on all endpoints
- [ ] Audit logging for security events
- [ ] Secure headers (CSP, X-Frame-Options, HSTS)
- [ ] No sensitive data in logs or error messages
- [ ] Session timeout implemented
- [ ] Brute force protection active

## Performance Guidelines

### Optimization Rules

1. **Buffer Management**
   - Use `sync.Pool` for buffer reuse
   - Default buffer size: 128KB (configurable in constants)
   - Zero-allocation where possible

2. **Connection Handling**
   - Connection pooling for external services
   - TCP_NODELAY enabled for low latency
   - Keep-alive connections with reasonable timeouts

3. **Concurrency**
   - Use goroutines for I/O-bound operations
   - Limit concurrent goroutines (use semaphores if needed)
   - Always use `sync.WaitGroup` for goroutine coordination

4. **Memory Management**
   - Pre-allocate slices with known capacity
   - Use `defer` for resource cleanup
   - Avoid memory leaks in long-running processes

### Performance Checklist

- [ ] Buffer pooling implemented for hot paths
- [ ] No unnecessary allocations in loops
- [ ] Efficient data structures chosen (maps vs slices)
- [ ] Concurrent operations used appropriately
- [ ] Resource cleanup with defer
- [ ] Connection limits enforced

## Code Quality Standards

### Naming Conventions

1. **Packages**: Lowercase, single word, no underscores
   - Good: `security`, `tunnel`, `utils`
   - Bad: `security_utils`, `tunnelManager`

2. **Types**: PascalCase, descriptive
   - Good: `ConnectionLimiter`, `AuditEvent`
   - Bad: `Limiter`, `Event`

3. **Functions**: CamelCase, verb-first for actions
   - Good: `ValidateToken()`, `GetClientIP()`
   - Bad: `TokenValidation()`, `ClientIPGetter()`

4. **Variables**: CamelCase, short but meaningful
   - Good: `conn`, `maxRetries`, `tunnelUUID`
   - Bad: `c`, `mr`, `tuid`

5. **Constants**: PascalCase for exported, UPPER_SNAKE for unexported
   - Good: `MaxConnectionsPerIP`, `defaultTimeout`

### Error Handling

1. **Always check errors**: Never ignore returned errors
2. **Wrap errors**: Use `fmt.Errorf("context: %w", err)`
3. **Specific error types**: Define custom errors for business logic
4. **No panic in production**: Recover from panics at entry points

```go
// Good
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to do something: %w", err)
}

// Bad
doSomething() // ignoring error
```

### Logging

1. **Structured logging**: Use JSON format for machine parsing
2. **Log levels**: Debug, Info, Warning, Error
3. **No sensitive data**: Never log passwords, tokens, or PII
4. **Context**: Include relevant IDs (session, request) in log entries

### Comments

1. **Document exported items**: All exported types, functions, and constants
2. **English only**: All comments and documentation in English
3. **Why, not what**: Explain intent, not obvious behavior
4. **Keep updated**: Comments must reflect current code

```go
// Good
// ValidateUUID checks if the provided string is a valid UUID v4 format.
// Returns false for empty strings or invalid formats.
func ValidateUUID(uuid string) bool

// Bad
// This function validates the UUID
func ValidateUUID(uuid string) bool
```

## Testing Requirements

### Test Coverage

- **Minimum 80% coverage**: All packages must have >80% test coverage
- **Critical paths 100%**: Security, authentication, and tunnel logic
- **Integration tests**: End-to-end tests for client-server communication

### Test Structure

```go
func TestFeature(t *testing.T) {
    // Arrange
    input := "test"
    expected := "result"
    
    // Act
    result, err := Feature(input)
    
    // Assert
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result != expected {
        t.Errorf("got %v, want %v", result, expected)
    }
}
```

### Test Categories

1. **Unit tests**: Individual functions, mocked dependencies
2. **Integration tests**: Component interactions
3. **Security tests**: Auth bypass attempts, injection attacks
4. **Performance tests**: Benchmark critical paths

## Configuration Management

### Environment Variables

All configuration must be environment-variable driven:

```go
// internal/constants/constants.go
const (
    DefaultHost = "localhost:8080"
    DefaultPort = "8080"
)

// Usage with override
host := utils.GetEnv("SSROK_HOST", constants.DefaultHost)
port := utils.GetEnv("PORT", constants.DefaultPort)
```

### No Hardcoded Values

- **Never** hardcode: URLs, ports, timeouts, credentials, secrets
- **Always** use constants from `internal/constants/`
- **Document** all environment variables in README.md

## Code Review Checklist

Before submitting PR:

- [ ] Code follows DRY principle (no duplication)
- [ ] SOLID principles applied
- [ ] Files under 300 lines
- [ ] Functions under 50 lines
- [ ] All error cases handled
- [ ] Input validated
- [ ] Security implications considered
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No hardcoded values
- [ ] English comments only
- [ ] Benchmarks added for performance-critical code

## Build and Release

### Makefile Commands

```bash
make build          # Build both binaries
make build-client   # Build client only
make build-server   # Build server only
make test           # Run all tests
make release        # Build release binaries for all platforms
make clean          # Clean build artifacts
```

### Release Process

1. Update version in `Makefile`
2. Run `make release`
3. Generate checksums: `shasum -a 256 dist/* > checksums.txt`
4. Update Homebrew formula with new URLs and SHA256
5. Create GitHub release with binaries

## Anti-Patterns (Forbidden)

1. **No global state**: Use dependency injection
2. **No init() side effects**: Only register types, no I/O
3. **No import cycles**: Refactor to avoid circular dependencies
4. **No panics**: Recover at boundaries, return errors
5. **No hardcoded strings**: Use constants
6. **No TODO without issue**: Create GitHub issue for TODOs
7. **No commented code**: Delete, don't comment out
8. **No magic numbers**: Use named constants

## Example: Proper Package Structure

```go
// internal/security/ratelimiter.go
package security

import (
    "sync"
    "time"
)

// ConnectionLimiter tracks and limits connections per IP.
// It is safe for concurrent use.
type ConnectionLimiter struct {
    mu          sync.RWMutex
    connections map[string]int
    maxConn     int
}

// NewConnectionLimiter creates a new limiter with the specified maximum.
func NewConnectionLimiter(maxConn int) *ConnectionLimiter {
    return &ConnectionLimiter{
        connections: make(map[string]int),
        maxConn:     maxConn,
    }
}

// TryConnect attempts to register a new connection for the given IP.
// Returns true if the connection is allowed, false if limit exceeded.
func (cl *ConnectionLimiter) TryConnect(ip string) bool {
    cl.mu.Lock()
    defer cl.mu.Unlock()
    
    if cl.connections[ip] >= cl.maxConn {
        return false
    }
    cl.connections[ip]++
    return true
}
```

## Questions?

If unclear about any guideline:
1. Check existing code in the repository
2. Refer to Go official style guide: https://go.dev/doc/effective_go
3. Ask in GitHub discussions

---

**Remember**: These guidelines exist to maintain code quality, security, and performance. When in doubt, prioritize security and clarity over cleverness.
