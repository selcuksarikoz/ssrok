package utils

import (
	"crypto/tls"
	"fmt"
	"net"

	"ssrok/internal/constants"
)

func DetectProtocol(host string, port int) bool {
	target := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{
		Timeout: constants.ProtocolDetectionTimeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})

	if err == nil {
		conn.Close()
		return true
	}

	return false
}
