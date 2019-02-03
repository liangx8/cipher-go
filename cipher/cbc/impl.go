package cbc

import (
	cip "crypto/cipher"
)

type (
	innerCBC struct {
		block cip.Block
	}
)
