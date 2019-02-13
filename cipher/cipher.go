package cipher

import (
	"io"
)

type (
	Cipher interface {
		// Wrap Reader facility
		DecryptReader(reader io.Reader) io.ReadCloser
		EncryptWriter(writer io.Writer) io.WriteCloser
	}
	errReader struct {
		err error
	}
	errWriter struct {
		err error
	}
)

func (e *errReader) Read(_ []byte) (int, error) {
	return 0, e.err
}
func (_ *errReader) Close() error {
	return nil
}
func (e *errWriter) Write(_ []byte) (int, error) {
	return 0, e.err
}
func (e *errWriter) Close() error {
	return nil
}
func ErrorReader(err error) io.ReadCloser {
	return &errReader{err}
}
func ErrorWriter(err error) io.WriteCloser {
	return &errWriter{err}
}
