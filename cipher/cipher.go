package cipher

import (
	"io"
)

type (
	Cipher interface {
		// Wrap Reader facility
		DecryptReader(reader io.Reader) io.Reader
		EncryptWriter(writer io.Writer) io.Writer
	}
)
