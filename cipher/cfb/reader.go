package cfb

import (
	cip "crypto/cipher"
	"errors"
	"github.com/liangx8/cipher-go/cipher"
	"io"
)

type readCloser struct {
	sr *cip.StreamReader
}

func (*readCloser) Close() error { return nil }
func (r *readCloser) Read(b []byte) (int, error) {
	return r.sr.Read(b)
}
func (c *innerCFBCipher) DecryptReader(reader io.Reader) io.ReadCloser {
	iv := make([]byte, c.block.BlockSize())
	num, err := reader.Read(iv)
	if err != nil {
		return cipher.ErrorReader(err)
	}
	if num != c.block.BlockSize() {
		return cipher.ErrorReader(cipherTooShortError)
	}
	stream := cip.NewCFBDecrypter(c.block, iv)

	return &readCloser{&cip.StreamReader{S: stream, R: reader}}
}

var cipherTooShortError = errors.New("cipher text too short")
