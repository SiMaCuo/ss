package tcprelay

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

const SS_TCP_CHUNK_LEN = 1452

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// WriteTo
type AeadDecryptor struct {
	*bufio.Reader
	cipher.AEAD
	nonce []byte
}

func (b *AeadDecryptor) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	ltl := 2 + b.Overhead()
	bs, err := b.Peek(ltl)
	if err != nil {
		log.Debug("peek length ciphertext failed: ", err)
		return 0, err
	}

	l, err := b.Open(bs[:0], b.nonce, bs, nil)
	if err != nil {
		log.Debug("decrypt length failed: ", err)
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(l))
	increment(b.nonce)
	b.Discard(ltl)

	bs, err = b.Peek(length + b.Overhead())
	if err != nil {
		log.Debugf("peek size %d bytes ciphertext failed: %s", length+b.Overhead(), err.Error())
		return 0, err
	}

	defer b.Discard(length + b.Overhead())
	plaintext, err := b.Open(bs[:0], b.nonce, bs, nil)
	if err != nil {
		log.Debugf("decrypt payload failed: %s", err.Error())
		return 0, err
	}
	increment(b.nonce)

	if len(plaintext) > len(p) {
		log.Debug("need more space")

		return 0, fmt.Errorf("need more space")
	}

	return copy(p, plaintext), nil
}

func (b *AeadDecryptor) WriteTo(w io.Writer) (amt int64, err error) {
	lenSecSize := 2 + b.Overhead()
	for {
		p, err := b.Peek(lenSecSize)
		if err != nil {
			return amt, err
		}

		_, err = b.Open(p[:0], b.nonce, p, nil)
		if err != nil {
			log.Debug("decrypt length error: %s", err.Error())
			return amt, err
		}

		payloadSize := int(binary.BigEndian.Uint16(p[0:]))
		increment(b.nonce)
		b.Discard(lenSecSize)

		p, err = b.Peek(payloadSize + b.Overhead())
		if err != nil {
			return amt, err
		}

		_, err = b.Open(p[:0], b.nonce, p, nil)
		if err != nil {
			log.Debug("decript payload err: %s", err.Error())
			return amt, err
		}
		increment(b.nonce)

		for pos := 0; pos < payloadSize; {
			nw, err := w.Write(p[:payloadSize])
			if err != nil {
				return amt, err
			}
			pos += nw
			amt += int64(nw)
		}
		b.Discard(payloadSize + b.Overhead())
	}

}

func NewAeadDecryptor(rd io.Reader, aead cipher.AEAD) *AeadDecryptor {
	return &AeadDecryptor{
		Reader: bufio.NewReaderSize(rd, 2048),
		AEAD:   aead,
		nonce:  make([]byte, aead.NonceSize()),
	}
}

// Readfrom
type AeadEncryptor struct {
	io.Writer
	cipher.AEAD
	nonce      []byte
	sealBuf    []byte
	lenSec     []byte
	payloadSec []byte
}

func NewAeadEncryptor(w io.Writer, aead cipher.AEAD) *AeadEncryptor {
	sealBuf := make([]byte, SS_TCP_CHUNK_LEN)
	return &AeadEncryptor{
		Writer:     w,
		AEAD:       aead,
		nonce:      make([]byte, aead.NonceSize()),
		sealBuf:    sealBuf,
		lenSec:     sealBuf[:2+aead.Overhead()],
		payloadSec: sealBuf[2+aead.Overhead():],
	}
}

func (b *AeadEncryptor) ReadFrom(r io.Reader) (amt int64, err error) {
	reader := bufio.NewReader(r)
	chunkSize := SS_TCP_CHUNK_LEN - 2*b.Overhead() - 2
	for {
		n, err := reader.Read(b.payloadSec[:chunkSize])
		if err != nil {
			return amt, err
		}

		if n == 0 {
			continue
		}

		binary.BigEndian.PutUint16(b.lenSec[:2], uint16(n))
		b.Seal(b.lenSec[:0], b.nonce, b.lenSec[:2], nil)
		increment(b.nonce)

		b.Seal(b.payloadSec[:0], b.nonce, b.payloadSec[:n], nil)
		increment(b.nonce)

		pos, secSize := 0, 2+2*b.Overhead()+n
		for pos < secSize {
			nw, err := b.Write(b.sealBuf[pos:secSize])
			if err != nil {
				return amt, err
			}
			pos += nw
			amt += int64(nw)
		}
	}

	return
}
