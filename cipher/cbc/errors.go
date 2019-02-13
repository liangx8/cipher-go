package cbc

import (
	"errors"
	"fmt"
)

func errorCreate(expected, actual int) error {
	return fmt.Errorf("Size of data doesn't pad to block size, expected block size %d but %d", expected, actual)
}

var cipherTooShortError = errors.New("Cipher data too short")
