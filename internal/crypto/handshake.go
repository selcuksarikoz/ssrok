package crypto

import (
	"fmt"
	"io"
	"net"
)

func Handshake(conn net.Conn, isServer bool) ([]byte, error) {
	// 1. Generate local key pair
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 2. Exchange public keys
	// We use a simple 32-byte exchange.

	var remotePub [32]byte

	if isServer {
		// Server first reads client's public key, then sends its own
		if _, err := io.ReadFull(conn, remotePub[:]); err != nil {
			return nil, fmt.Errorf("failed to read client public key: %w", err)
		}
		if _, err := conn.Write(pub[:]); err != nil {
			return nil, fmt.Errorf("failed to send server public key: %w", err)
		}
	} else {
		// Client first sends its public key, then reads server's
		if _, err := conn.Write(pub[:]); err != nil {
			return nil, fmt.Errorf("failed to send client public key: %w", err)
		}
		if _, err := io.ReadFull(conn, remotePub[:]); err != nil {
			return nil, fmt.Errorf("failed to read server public key: %w", err)
		}
	}

	// 3. Derive shared secret
	shared, err := DeriveSharedSecret(priv, remotePub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	return shared[:], nil
}
