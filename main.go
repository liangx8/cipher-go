package main

import (
	"fmt"
	"github.com/liangx8/cipher-go/cipher/cbc"
)

func main() {
	_, err := cbc.NewAESCipher(key32)
	if err != nil {
		fmt.Println(err)
	}
}

var key32 = []byte(keyStr)

const (
	keyStr = "01234567890123456789012345678901"
)
