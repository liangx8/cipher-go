package cfb

import (
	cip "crypto/cipher"
	"crypto/rand"
	"github.com/liangx8/cipher-go/cipher"
	"io"
)

type writeCloser struct {
	sw *cip.StreamWriter
}

func (w *writeCloser) Close() error {
	return nil
}
func (w *writeCloser) Write(b []byte) (int, error) {
	return w.sw.Write(b)
}
func (c *innerCFBCipher) EncryptWriter(writer io.Writer) io.WriteCloser {
	iv := make([]byte, c.block.BlockSize())
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return cipher.ErrorWriter(err)
	}
	num, err := writer.Write(iv)
	if err != nil {
		return cipher.ErrorWriter(err)
	}
	if num < c.block.BlockSize() {
		return cipher.ErrorWriter(cipherTooShortError)
	}
	stream := cip.NewCFBEncrypter(c.block, iv)
	return &writeCloser{sw: &cip.StreamWriter{S: stream, W: writer}}
}
