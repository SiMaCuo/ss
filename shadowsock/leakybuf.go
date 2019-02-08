package shadowsock

type LeakyBuf struct {
	freeList chan []byte
}

const leakyBufSize int = 320
const maxNBufs int = 64

var leakyBuf = newLeakyBuf()

func newLeakyBuf() *LeakyBuf {
	return &LeakyBuf{
		freeList: make(chan []byte, maxNBufs),
	}
}

func (lb *LeakyBuf) Get() (b []byte) {
	select {
	case b = <-lb.freeList:

	default:
		b = make([]byte, leakyBufSize)
	}

	return
}

func (lb *LeakyBuf) Put(b []byte) {
	if len(b) != leakyBufSize {
		panic("invalid leaky buffer size")
	}

	select {
	case lb.freeList <- b:

	default:
	}
}
