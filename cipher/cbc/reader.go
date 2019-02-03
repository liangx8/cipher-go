package cbc

import (
	cip "crypto/cipher"
	"io"
)

type (
	innerCBCReader struct {
		raw  io.Reader
		mode cip.BlockMode
	}
	errReader struct {
		err error
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
func (r *innerCBCReader) Read(p []byte) (int, error) {
	num, err := r.raw.Read(p)
	if err != nil {
		return 0, err
	}
	ciphertext := p[:num]
	r.mode.CryptBlocks(ciphertext, ciphertext)
	return num, nil
}

func (e *errReader) Read(p []byte) (int, error) {
	return 0, e.err
}
