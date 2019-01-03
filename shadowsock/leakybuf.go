package shadowsocks

type leakyBuf struct {
	freeList chan []byte
}

const leakyBufSize int32 = 4096
const maxNBufs int32 = 1024

var leakyBuf = newLeakyBuf()

func newLeakyBuf() *leakyBuf {
	return &leakyBuf {
		freeList = make(chan []byte, maxNBufs)
	}
}

func (lb *leakyBuf) Get() (b []byte) {
	select {
	case b = <-lb.freeList:

	default:
		b = make([]byte, leakyBufSize)
	}

	return
}

func (lb *leakyBuf) Put(b []byte) {
	if len(b) != leakyBufSize {
		panic!("invalid leaky buffer size")
	}

	select {
	case lb.freeList <- b:

	default:
	}
}



