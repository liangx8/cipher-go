package cipher_test

import (
	"bytes"
	"fmt"
	"github.com/liangx8/cipher-go/cipher"
	"github.com/liangx8/cipher-go/cipher/cbc"
	"io"
	"testing"
)

var key32 = []byte(keyStr)

func TestByteBuffer(t *testing.T) {
	buf := new(bytes.Buffer)
	buf.Write(key32)
	buf.Write(key32)
	mem := make([]byte, 100)
	num, err := buf.Read(mem)

	if num != 64 {
		t.Fatalf("expect 64 but %d", num)
	}
	if err != nil {
		t.Fatal(err)
	}
	num, err = buf.Read(mem)
	if num > 0 {
		t.Fatalf("expect 0 but %d", num)
	}
	if err != io.EOF {
		t.Fatalf("expected io.EOF but %v", err)
	}
}
func TestCBCAES(t *testing.T) {
	ci, _ := cbc.NewAESCipher(key32[:16])
	aesCBC(t, ci, "AES-128")
	ci, _ = cbc.NewAESCipher(key32[:24])
	aesCBC(t, ci, "AES-192")
	ci, _ = cbc.NewAESCipher(key32)
	aesCBC(t, ci, "AES-256")
}
func aesCBC(t *testing.T, ci cipher.Cipher, msg string) {

	buf := new(bytes.Buffer)
	w := ci.EncryptWriter(buf)
	defer w.Close()
	_, err := fmt.Fprint(w, src)
	if err != nil {
		t.Fatal(err)
	}

	r := ci.DecryptReader(buf)
	out := make([]byte, len(src))
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
	aesCBC(t, ci, "DES")
}
func TestCBCFail(t *testing.T) {
	ci, _ := cbc.NewAESCipher(key32)
	buf := new(bytes.Buffer)
	buf.Write(key32)
	buf.Write(key32)
	r := ci.DecryptReader(buf)
	tmp := make([]byte, 60)
	_, err := r.Read(tmp)
	if err != nil {
		t.Error(err)
	}
}

func TestCBC(t *testing.T) {
	ci, _ := cbc.NewAESCipher(key32)
	cr := ci.DecryptReader(createBuffer(cipher.LEAKYBUFFER_SIZE))
	defer cr.Close()
	buf := make([]byte, 400)
	total := 0
	for {
		num, err := cr.Read(buf)
		total += num
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	//16 is size of IV
	if total+16 != cipher.LEAKYBUFFER_SIZE {
		t.Fatalf("expected %d but %d", cipher.LEAKYBUFFER_SIZE, total+16)
	}
}
func createBuffer(num int) io.Reader {
	buf := new(bytes.Buffer)
	mem := make([]byte, 1024)
	x := 0
	for i := 0; i < num; i++ {
		if x == 1024 {
			buf.Write(mem)
			x = 0
		}
		mem[x] = byte(i % 256)
		x++
	}
	if x > 0 {
		buf.Write(mem[:x])
	}
	return buf
}

const (
	src    = "hello world ...................."
	keyStr = "01234567890123456789012345678901"
)
