package screen

import (
	"bytes"
	"fmt"
	"image/jpeg"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"time"

	"github.com/kbinani/screenshot"
)

// StartStreamServer starts a local HTTP server that serves the screen as an MJPEG stream on /stream.
func StartStreamServer(fps int, quality int) (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		streamHandler(w, r, fps, quality)
	})

	go func() {
		if err := http.Serve(listener, mux); err != nil {
			log.Printf("Screen stream server error: %v", err)
		}
	}()

	return port, nil
}

func streamHandler(w http.ResponseWriter, r *http.Request, fps int, quality int) {
	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=frame")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	mw := multipart.NewWriter(w)
	if err := mw.SetBoundary("frame"); err != nil {
		log.Printf("Failed to set boundary: %v", err)
		return
	}

	if fps <= 0 {
		fps = 10
	}
	if quality <= 0 || quality > 100 {
		quality = 60
	}

	frameInterval := time.Duration(1000/fps) * time.Millisecond
	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Capture primary display
		bounds := screenshot.GetDisplayBounds(0)
		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			log.Printf("\n❌ Failed to capture screen: %v\n", err)
			log.Printf("⚠️  macOS Users: If you see 'cannot capture display', you need to grant Screen Recording permissions.\n")
			log.Printf("👉 Go to: System Settings -> Privacy & Security -> Screen Recording\n")
			log.Printf("👉 And enable permission for your Terminal (e.g., iTerm, Terminal.app, or VSCode).\n\n")
			time.Sleep(2 * time.Second) // Don't spam logs too fast
			continue
		}

		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
			log.Printf("Failed to encode JPEG: %v", err)
			continue
		}

		partHeader := make(textproto.MIMEHeader)
		partHeader.Add("Content-Type", "image/jpeg")
		partHeader.Add("Content-Length", fmt.Sprintf("%d", buf.Len()))

		partWriter, err := mw.CreatePart(partHeader)
		if err != nil {
			log.Printf("Failed to create multipart part: %v", err)
			break
		}

		if _, err := partWriter.Write(buf.Bytes()); err != nil {
			log.Printf("Failed to write image data: %v", err)
			break
		}

		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}
