package tunnel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"sync"

	"ssrok/internal/constants"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, constants.CopyBufferSize)
	},
}

func GetBuffer() []byte {
	return bufferPool.Get().([]byte)
}

func PutBuffer(buf []byte) {
	if cap(buf) >= constants.CopyBufferSize {
		bufferPool.Put(buf[:constants.CopyBufferSize])
	}
}

var bytesBufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 4096))
	},
}

func GetBytesBuffer() *bytes.Buffer {
	buf := bytesBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func PutBytesBuffer(buf *bytes.Buffer) {
	if buf.Cap() <= 65536 {
		bytesBufferPool.Put(buf)
	}
}

var bufioReaderPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReaderSize(nil, 32768)
	},
}

func GetBufioReader(r interface{ Read([]byte) (int, error) }) *bufio.Reader {
	br := bufioReaderPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

func PutBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	bufioReaderPool.Put(br)
}

var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		gz, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
		return gz
	},
}

func GetGzipWriter(w interface{ Write([]byte) (int, error) }) *gzip.Writer {
	gz := gzipWriterPool.Get().(*gzip.Writer)
	gz.Reset(w)
	return gz
}

func PutGzipWriter(gz *gzip.Writer) {
	gz.Close()
	gzipWriterPool.Put(gz)
}
