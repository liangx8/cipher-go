package cbc

import (
	cip "crypto/cipher"
	"crypto/rand"
	"github.com/liangx8/cipher-go/cipher"
	"io"
)

type (
	innerCBCWriter struct {
		raw    io.Writer
		mode   cip.BlockMode
		buf    []byte
		bufIdx int
	}
)

func (ci *innerCBC) EncryptWriter(writer io.Writer) io.WriteCloser {
	iv := make([]byte, ci.block.BlockSize())
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return cipher.ErrorWriter(err)
	}
	num, err := writer.Write(iv)
	if err != nil {
		return cipher.ErrorWriter(err)
	}
	if num < ci.block.BlockSize() {
		// 接收方放弃即意味后面的内容无需再发送
		return cipher.ErrorWriter(io.ErrUnexpectedEOF)
	}

	mode := cip.NewCBCEncrypter(ci.block, iv)
	return &innerCBCWriter{
		raw:    writer,
		mode:   mode,
		buf:    cipher.LB.Get(),
		bufIdx: 0,
	}
}
func (w *innerCBCWriter) Write(p []byte) (int, error) {
	pIdx := 0
	totalSize := 0
	for {
		num := copy(w.buf[w.bufIdx:], p[pIdx:])
		w.bufIdx += num
		pIdx += num
		if w.bufIdx == cipher.LEAKYBUFFER_SIZE {
			w.mode.CryptBlocks(w.buf, w.buf)
			total, err := w.raw.Write(w.buf)
			if err != nil {
				return 0, err
			}
			w.bufIdx = 0
			totalSize += total
		} else {
			remand := w.bufIdx % w.mode.BlockSize()
			blockSize := w.bufIdx - remand
			if blockSize > 0 {
				w.mode.CryptBlocks(w.buf[:blockSize], w.buf[:blockSize])
				total, err := w.raw.Write(w.buf[:blockSize])
				if err != nil {
					return 0, err
				}
				totalSize += total
			}
			if remand > 0 {
				copy(w.buf[:remand], w.buf[blockSize:w.bufIdx])
			}
			w.bufIdx = remand
			break
		}
	}
	return totalSize, nil
}
func (w *innerCBCWriter) Close() error {
	cipher.LB.Put(w.buf)
	return nil
}
