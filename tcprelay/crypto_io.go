package tcprelay

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
	reader net.Conn
	cipher.AEAD
	nonce []byte
	name  string
}

func (b *AeadDecryptor) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	ltl := 2 + b.Overhead()
	SetReadDeadLine(b.reader)
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

	SetReadDeadLine(b.reader)
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
		SetReadDeadLine(b.reader)
		p, err := b.Peek(lenSecSize)
		if err != nil {
			log.Debugf("%s, read length section, error: %s", b.name, err.Error())
			break
		}

		_, err = b.Open(p[:0], b.nonce, p, nil)
		if err != nil {
			log.Debugf("%s, decrypt length error: %s", b.name, err.Error())
			break
		}

		payloadSize := int(binary.BigEndian.Uint16(p[0:]))
		increment(b.nonce)
		b.Discard(lenSecSize)

		SetReadDeadLine(b.reader)
		p, err = b.Peek(payloadSize + b.Overhead())
		if err != nil {
			log.Debugf("%s, read payload %d bytes, error: %s", b.name, payloadSize, err.Error())
			break
		}

		_, err = b.Open(p[:0], b.nonce, p, nil)
		if err != nil {
			log.Debug("%s, decript payload err: %s", b.name, err.Error())
			break
		}
		increment(b.nonce)

		_, err = w.Write(p[:payloadSize])
		if err != nil {
			log.Debugf("%s write error: %s", b.name, err.Error())
			break
		}
		amt += int64(payloadSize)
		b.Discard(payloadSize + b.Overhead())
	}

	log.Debugf("%s, done writeto %.4fKB", b.name, float64(amt)/1024)

	return
}

func (b *AeadDecryptor) setName(name string) {
	b.name = name
}

func NewAeadDecryptor(rd net.Conn, aead cipher.AEAD) *AeadDecryptor {
	return &AeadDecryptor{
		Reader: bufio.NewReaderSize(rd, 4096),
		reader: rd,
		AEAD:   aead,
		nonce:  make([]byte, aead.NonceSize()),
		name:   "*",
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
	name       string
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
		name:       "*",
	}
}

func (b *AeadEncryptor) ReadFrom(r io.Reader) (amt int64, err error) {
	reader := bufio.NewReader(r)
	chunkSize := SS_TCP_CHUNK_LEN - 2*b.Overhead() - 2
	conn, typOk := r.(net.Conn)
	for {
		if typOk {
			SetReadDeadLine(conn)
		}

		n, err := reader.Read(b.payloadSec[:chunkSize])
		if n > 0 {
			binary.BigEndian.PutUint16(b.lenSec[:2], uint16(n))
			b.Seal(b.lenSec[:0], b.nonce, b.lenSec[:2], nil)
			increment(b.nonce)

			b.Seal(b.payloadSec[:0], b.nonce, b.payloadSec[:n], nil)
			increment(b.nonce)

			secSize := 2 + 2*b.Overhead() + n
			_, err = b.Write(b.sealBuf[:secSize])
			if err == nil {
				amt += int64(secSize)
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() {
					if n > 0 {
						continue
					}
				}
			}

			log.Debugf("%s done, %s, readfrom %.4fKB", b.name, err.Error(), float64(amt)/1024)
			break
		}
	}

	return
}

func (b *AeadEncryptor) setName(name string) {
	b.name = name
}
