package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"ssrok/internal/constants"
	"ssrok/internal/types"
)

func RegisterTunnel(serverURL string, config types.ConfigRequest, skipTLSVerify bool) (*types.ConfigResponse, error) {
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	if skipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Post(
		serverURL+constants.EndpointRegister,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bytes.TrimSpace(body)))
	}

	var result types.ConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
