package cbc

import (
	cip "crypto/cipher"
	"crypto/rand"
	"io"
)

type (
	errWriter struct {
		err error
	}
	innerCBCWriter struct {
		raw  io.Writer
		mode cip.BlockMode
	}
)

func (cipher *innerCBC) EncryptWriter(writer io.Writer) io.Writer {
	iv := make([]byte, cipher.block.BlockSize())
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return &errWriter{err}
	}
	num, err := writer.Write(iv)
	if err != nil {
		return &errWriter{err}
	}
	if num < cipher.block.BlockSize() {
		return &errWriter{ciperTooShortError}
	}
	mode := cip.NewCBCEncrypter(cipher.block, iv)
	return &innerCBCWriter{raw: writer, mode: mode}
}
func (w *innerCBCWriter) Write(p []byte) (int, error) {
	w.mode.CryptBlocks(p, p)
	num, err := w.raw.Write(p)
	if err != nil {
		return 0, err
	}
	return num, nil
}
func (e *errWriter) Write(p []byte) (int, error) {
	return 0, e.err
}
