package utils

import (
	"bytes"
)

type LimitedBuffer struct {
	Buf     *bytes.Buffer
	Limit   int
	Written int
}

func (l *LimitedBuffer) Write(p []byte) (n int, err error) {
	if l.Written >= l.Limit {
		return len(p), nil
	}
	remaining := l.Limit - l.Written
	if len(p) > remaining {
		l.Buf.Write(p[:remaining])
		l.Written += remaining
		return len(p), nil
	}
	n, err = l.Buf.Write(p)
	l.Written += n
	return n, err
}
