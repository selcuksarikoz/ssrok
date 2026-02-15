package tunnel

import (
	"sync"

	"ssrok/internal/constants"
)

// bufferPool for zero-allocation buffer reuse
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, constants.CopyBufferSize)
	},
}

// GetBuffer retrieves a buffer from the pool
func GetBuffer() []byte {
	return bufferPool.Get().([]byte)
}

// PutBuffer returns a buffer to the pool
func PutBuffer(buf []byte) {
	if cap(buf) >= constants.CopyBufferSize {
		bufferPool.Put(buf[:constants.CopyBufferSize])
	}
}
