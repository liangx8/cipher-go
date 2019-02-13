package cbc

import (
	"crypto/aes"
	cip "crypto/cipher"
	"crypto/des"
	"github.com/liangx8/cipher-go/cipher"
)

type (
	innerCBC struct {
		block cip.Block
	}
)

// Create new AES algorithm CBC cipher, key should be size in 16,24,32
// crypted data must pad to key size or panic occured
func NewAESCipher(key []byte) (cipher.Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &innerCBC{block}, nil
}
func NewDESCipher(key []byte) (cipher.Cipher, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &innerCBC{block}, nil
}
