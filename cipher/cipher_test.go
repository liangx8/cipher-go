package cipher_test

import (
	"bytes"
	"fmt"
	"github.com/liangx8/cipher-go/cipher"
	"github.com/liangx8/cipher-go/cipher/cbc"
	"testing"
)

const src = "01234567890123456789012345678901"

var key32 = []byte(src)

func TestCBCAES(t *testing.T) {
	ci, _ := cbc.NewAESCipher(key32[:16])
	aesCBC(16, t, ci, "AES-128")
	ci, _ = cbc.NewAESCipher(key32[:32])
	aesCBC(32, t, ci, "AES-256")
}
func aesCBC(num int, t *testing.T, ci cipher.Cipher, msg string) {

	buf := new(bytes.Buffer)
	w := ci.EncryptWriter(buf)
	_, err := fmt.Fprint(w, src)
	if err != nil {
		t.Fatal(err)
	}

	r := ci.DecryptReader(buf)
	out := make([]byte, len(key32))
	_, err = r.Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != src {
		t.Fatal(msg)
	}
}
func TestCBCDES(t *testing.T) {
	ci, _ := cbc.NewDESCipher(key32[:8])
	aesCBC(8, t, ci, "DES")
}
