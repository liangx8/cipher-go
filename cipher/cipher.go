package cipher

import (
	cip "crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type (
	Cipher interface {
		// Wrap Reader facility
		DecryptReader(reader io.Reader) io.Reader
		EncryptWriter(writer io.Writer) io.Writer
	}
	innerCBC struct {
		block cip.Block
	}
	innerCBCReader struct {
		raw  io.Reader
		mode cip.BlockMode
	}
	errReader struct {
		err error
	}
	errWriter struct {
		err error
	}
	innerCBCWriter struct {
		raw  io.Writer
		mode cip.BlockMode
	}
)

func (cipher *innerCBC) DecryptReader(reader io.Reader) io.Reader {
	iv := make([]byte, cipher.block.BlockSize())
	num, err := reader.Read(iv)
	if err != nil {
		return &errReader{err}
	}
	if num < cipher.block.BlockSize() {
		return &errReader{ciperTooShortError}
	}
	mode := cip.NewCBCDecrypter(cipher.block, iv)
	return &innerCBCReader{raw: reader, mode: mode}
}
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
func (r *innerCBCReader) Read(p []byte) (int, error) {
	num, err := r.raw.Read(p)
	if err != nil {
		return 0, err
	}
	ciphertext := p[:num]
	r.mode.CryptBlocks(ciphertext, ciphertext)
	return num, nil
}
func (w *innerCBCWriter) Write(p []byte) (int, error) {
	w.mode.CryptBlocks(p, p)
	num, err := w.raw.Write(p)
	if err != nil {
		return 0, err
	}
	return num, nil
}

var ciperTooShortError = errors.New("Cipher text too short")

func (e *errReader) Read(p []byte) (int, error) {
	return 0, e.err
}
func (e *errWriter) Write(p []byte) (int, error) {
	return 0, e.err
}
