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

func (b *AeadDecryptor) WriteTo(w io.Writer) (n int64, err error) {
	n, ltl := 0, 2+b.Overhead()
	log.Debug("i'm in WriteTo routine")
	for {
		p, err := b.Peek(ltl)
		if err != nil {
			break
		}

		_, err = b.Open(p[:0], b.nonce, p, nil)
		if err != nil {
			log.Debug("decrypt length error: %s", err.Error())
			break
		}

		length := int(binary.BigEndian.Uint16(p[0:]))
		increment(b.nonce)
		// do not discard early
		b.Discard(ltl)

		p, err = b.Peek(length + b.Overhead())
		if err != nil {
			break
		}

		_, err = b.Open(p[:0], b.nonce, p, nil)
		if err != nil {
			log.Debug("decript payload err: %s", err.Error())
			break
		}
		increment(b.nonce)
		nw, err := w.Write(p[:length])
		log.Debugf("write to web %d byte", nw)
		n += int64(nw)
		b.Discard(length + b.Overhead())
		if err != nil {
			break
		}
	}

	return n, err
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
	nonce []byte
	buf   []byte
}

func NewAeadEncryptor(w io.Writer, aead cipher.AEAD) *AeadEncryptor {
	return &AeadEncryptor{
		Writer: w,
		AEAD:   aead,
		nonce:  make([]byte, aead.NonceSize()),
		buf:    make([]byte, SS_TCP_CHUNK_LEN),
	}
}

func (b *AeadEncryptor) ReadFrom(r io.Reader) (n int64, err error) {
	log.Debug("i'm in ReadFrom routine")
	rd := bufio.NewReaderSize(r, 2048)
	chunk_len := SS_TCP_CHUNK_LEN - 2*b.Overhead() - 2
	for {
		plaintext, err := rd.Peek(chunk_len)
		payloadLen := len(plaintext)
		if payloadLen > 0 {
			binary.BigEndian.PutUint16(b.buf[:2], uint16(payloadLen))
			b.Seal(b.buf[:0], b.nonce, b.buf[:2], nil)
			log.Debugf("seal %d byte, nonce %v, lenth %v", payloadLen, b.nonce, b.buf[:2+b.Overhead()])
			increment(b.nonce)

			b.Seal(b.buf[:2+b.Overhead()], b.nonce, plaintext, nil)
			log.Debugf("seal payload, nonce %v", b.nonce)
			increment(b.nonce)
			rd.Discard(payloadLen)

			nw, wd_err := b.Write(b.buf[:2+2*b.Overhead()+payloadLen])
			log.Debugf("read from web %d, total weite %d", payloadLen, nw)
			n += int64(nw)
			if wd_err != nil && err == nil {
				err = wd_err
			}
		}

		if err != nil {
			break
		}
	}

	return n, err
}
