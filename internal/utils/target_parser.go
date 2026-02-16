package utils

import (
	"fmt"
	"net"
	"strconv"

	"ssrok/internal/constants"
)

func ParseTarget(arg string) (string, int, error) {
	var targetHost string
	var targetPort int

	if p, err := strconv.Atoi(arg); err == nil {
		targetHost = constants.DefaultTargetHost
		targetPort = p
	} else {
		host, portStr, err := net.SplitHostPort(arg)
		if err != nil {
			return "", 0, fmt.Errorf("invalid argument: %s", arg)
		}
		if host == "" {
			targetHost = constants.DefaultTargetHost
		} else {
			targetHost = host
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port number: %s", portStr)
		}
		targetPort = p
	}

	if targetPort < constants.MinPort || targetPort > constants.MaxPort {
		return "", 0, fmt.Errorf("port number out of range: %d", targetPort)
	}

	return targetHost, targetPort, nil
}
