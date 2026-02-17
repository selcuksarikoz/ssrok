package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"ssrok/internal/constants"
	"ssrok/internal/security"
	"ssrok/internal/session"
	"ssrok/internal/tunnel"
	"ssrok/internal/utils"
)

type Server struct {
	Store          session.StoreInterface
	Tunnels        map[string]*tunnel.Tunnel
	TunnelMu       sync.RWMutex
	Host           string
	Port           string
	UseTLS         bool
	Templates      *TemplateManager
	ConnLimiter    *security.ConnectionLimiter
	BruteProtector *security.BruteForceProtector
	AuditLogger    *security.AuditLogger
}

func NewServer() (*Server, error) {
	store, err := session.NewStore()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize session store: %w", err)
	}

	tm, err := NewTemplateManager()
	if err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	auditLogger, err := security.GetAuditLogger()
	if err != nil {
		log.Printf("Warning: Failed to initialize audit logger: %v", err)
	}

	s := &Server{
		Store:          store,
		Tunnels:        make(map[string]*tunnel.Tunnel),
		Templates:      tm,
		ConnLimiter:    security.NewConnectionLimiter(constants.MaxConnectionsPerIP),
		BruteProtector: security.NewBruteForceProtector(constants.MaxAuthAttempts, constants.BlockDuration),
		AuditLogger:    auditLogger,
	}

	s.Store.OnExpire(func(uuid string) {
		s.TunnelMu.Lock()
		if t, ok := s.Tunnels[uuid]; ok {
			t.Close()
			delete(s.Tunnels, uuid)
			log.Printf("🗑 Tunnel closed (expired): %s", uuid)
		}
		s.TunnelMu.Unlock()
	})

	return s, nil
}

func (s *Server) Run() {
	s.Host = utils.GetEnv("SSROK_SERVER", constants.DefaultHost)
	s.Host = strings.TrimPrefix(s.Host, "http://")
	s.Host = strings.TrimPrefix(s.Host, "https://")

	if idx := strings.LastIndex(s.Host, ":"); idx > 0 {
		s.Host = s.Host[:idx]
	}

	s.Port = utils.GetEnv("PORT", constants.DefaultPort)
	certFile := utils.GetEnv("SSROK_CERT_FILE", "certs/server.crt")
	keyFile := utils.GetEnv("SSROK_KEY_FILE", "certs/server.key")

	mux := http.NewServeMux()
	mux.HandleFunc(constants.EndpointRegister, s.HandleRegister)
	mux.HandleFunc(constants.EndpointWebSocket, s.HandleWebSocket)
	mux.HandleFunc(constants.EndpointRoot, s.HandleTunnel)

	var handler http.Handler = mux
	handler = RecoveryMiddleware(handler)
	handler = CorsMiddleware(handler)
	handler = security.SecurityHeaders(handler)
	handler = GzipMiddleware(handler)

	enableTLS := strings.ToLower(utils.GetEnv("SSROK_ENABLE_TLS", "false")) == "true"
	useTLS := false

	if enableTLS {
		if _, err := os.Stat(certFile); err == nil {
			if _, err := os.Stat(keyFile); err == nil {
				useTLS = true
			}
		}

		if !useTLS {
			log.Printf("Warning: SSROK_ENABLE_TLS is true but certs not found at %s", certFile)
		}
	}
	s.UseTLS = useTLS

	var h2Handler http.Handler
	if useTLS {
		h2Handler = handler
	} else {
		h2Handler = h2c.NewHandler(handler, &http2.Server{})
	}

	server := &http.Server{
		Addr:              ":" + s.Port,
		Handler:           h2Handler,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if useTLS {
		log.Printf("🔒 HTTPS enabled (HTTP/2)")
		go func() {
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		}()
	} else {
		log.Printf("🌐 HTTP mode (HTTP/2 enabled)")
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}()
	}

	log.Printf("🚀 ssrok server starting on :%s", s.Port)

	<-sigChan
	log.Println("🛑 Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	s.Cleanup()
	log.Println("✅ Server stopped")
}

func (s *Server) Cleanup() {
	s.TunnelMu.Lock()
	defer s.TunnelMu.Unlock()
	for _, t := range s.Tunnels {
		t.Close()
	}
	s.Store.Close()
}
