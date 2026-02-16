package utils

import (
	"compress/gzip"
	"io"
	"net/http"
)

type GzipResponseWriter struct {
	http.ResponseWriter
	*gzip.Writer
}

func (w *GzipResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *GzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (w *GzipResponseWriter) Flush() {
	w.Writer.Flush()
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func CopyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	return io.CopyBuffer(dst, src, buf)
}
