package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// SecureConn wraps a net.Conn with ChaCha20-Poly1305 encryption.
type SecureConn struct {
	net.Conn
	aead    cipher.AEAD
	readBuf []byte
}

func NewSecureConn(conn net.Conn, key []byte) (*SecureConn, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &SecureConn{
		Conn: conn,
		aead: aead,
	}, nil
}

// Write encrypts and writes the data.
func (s *SecureConn) Write(p []byte) (n int, err error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}

	encrypted := s.aead.Seal(nil, nonce, p, nil)

	// Send nonce + encrypted data
	length := uint32(len(encrypted))
	lenBuf := []byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}

	if _, err := s.Conn.Write(lenBuf); err != nil {
		return 0, err
	}
	if _, err := s.Conn.Write(nonce); err != nil {
		return 0, err
	}
	if _, err := s.Conn.Write(encrypted); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (s *SecureConn) Read(p []byte) (n int, err error) {
	if len(s.readBuf) > 0 {
		n = copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	// Read length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(s.Conn, lenBuf); err != nil {
		return 0, err
	}
	length := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])

	// Read nonce
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(s.Conn, nonce); err != nil {
		return 0, err
	}

	// Read encrypted data
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(s.Conn, encrypted); err != nil {
		return 0, err
	}

	decrypted, err := s.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return 0, fmt.Errorf("decryption failed: %w", err)
	}

	n = copy(p, decrypted)
	if n < len(decrypted) {
		s.readBuf = decrypted[n:]
	}

	return n, nil
}

// GenerateKeyPair generates a X25519 key pair.
func GenerateKeyPair() (privateKey, publicKey [32]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey, nil
}

// DeriveSharedSecret derives a shared secret using X25519.
func DeriveSharedSecret(privateKey, remotePublicKey [32]byte) ([32]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey[:], remotePublicKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	var res [32]byte
	copy(res[:], sharedSecret)
	return res, nil
}
