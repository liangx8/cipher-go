package cipher

type (
	LeakyBuffer interface {
		Get() []byte
		Put(b []byte)
	}
	innerLeakyBuffer struct {
		bufSize  int
		freeList chan []byte
	}
)

const LEAKYBUFFER_SIZE = 32 * 512

var LB LeakyBuffer = &innerLeakyBuffer{bufSize: LEAKYBUFFER_SIZE, freeList: make(chan []byte, 20)}

func (lb *innerLeakyBuffer) Get() (b []byte) {
	select {
	case b = <-lb.freeList:
	default:
		b = make([]byte, lb.bufSize)
	}
	return
}
func (lb *innerLeakyBuffer) Put(b []byte) {
	if len(b) != lb.bufSize {
		panic("LeakyBuffer Put():buffer size incorrected")
	}
	select {
	case lb.freeList <- b:
	default:
	}
	return
}
