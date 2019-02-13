package cbc

import (
	cip "crypto/cipher"
	"github.com/liangx8/cipher-go/cipher"
	"io"
)

type (
	innerCBCReader struct {
		raw  io.Reader
		mode cip.BlockMode
		// 存放leakybuffer提取的缓存，因为块模式必须以BlockSize的整倍数来运算
		// 但是读写的流不一定是，因此使用一个符合这个规则的缓存
		buf     []byte
		bufSize int
		bufIdx  int
	}
)

func (ci *innerCBC) DecryptReader(reader io.Reader) io.ReadCloser {
	iv := make([]byte, ci.block.BlockSize())
	num, err := reader.Read(iv)
	if err != nil {
		return cipher.ErrorReader(err)
	}
	if num < ci.block.BlockSize() {
		return cipher.ErrorReader(cipherTooShortError)
	}
	mode := cip.NewCBCDecrypter(ci.block, iv)
	return &innerCBCReader{
		raw:     reader,
		mode:    mode,
		buf:     cipher.LB.Get(),
		bufSize: 0,
		bufIdx:  0,
	}
}
func (r *innerCBCReader) Close() error {
	cipher.LB.Put(r.buf) // gaven back to leaky buffer, and the content of buffer will be discarded
	return nil
}
func (r *innerCBCReader) Read(p []byte) (int, error) {
	// FIXME: working on here
	pCnt := len(p)
	pPos := 0
	reachEnd := false
	for {
		if reachEnd {
			break
		}
		if r.bufSize == r.bufIdx {
			num, err := r.raw.Read(r.buf)
			if err != nil {
				return 0, err
			}
			if num%r.mode.BlockSize() != 0 {
				return 0, errorCreate(r.mode.BlockSize(), num)
			}
			r.bufSize = num
			r.bufIdx = 0
			r.mode.CryptBlocks(r.buf[:num], r.buf[:num])
		}
		if r.bufSize < len(r.buf) {
			reachEnd = true
		}
		cnt := copy(p[pPos:pCnt], r.buf[r.bufIdx:r.bufSize])
		pPos = pPos + cnt
		r.bufIdx = r.bufIdx + cnt
		if pPos == pCnt {
			break
		}
		if pPos > pCnt {
			panic("Impossible situation")
		}
	}
	return pPos, nil
}
