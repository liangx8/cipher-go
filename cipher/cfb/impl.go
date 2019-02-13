package cfb

import (
	"crypto/aes"
	cip "crypto/cipher"
	"github.com/liangx8/cipher-go/cipher"
)

type innerCFBCipher struct {
	block cip.Block
}

func NewAESCipher(key []byte) (cipher.Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &innerCFBCipher{block}, nil
}
