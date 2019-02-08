package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	_ "crypto/sha1"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	CIPHER_AES_256_GCM             = "aes-256-gcm"
	CIPHER_CHACHA20_IETF_POLY1305  = "chacha20-ietf-poly1305"
	CIPHER_XCHACHA20_IETF_POLY1305 = "xchacha20-ietf-poly1305"
)

type CipherMethodError string

func (e CipherMethodError) Error() string {
	msg := fmt.Sprintf("cipher method only support: \n\t%s \n\t%s \n\t%s \n\tbut: %s\n",
		CIPHER_AES_256_GCM,
		CIPHER_CHACHA20_IETF_POLY1305,
		CIPHER_XCHACHA20_IETF_POLY1305,
		string(e))
	return msg
}

// copy from shadowsock-go
func BytesToKey(bytes []byte, key_len uint32) (key []byte) {
	key = make([]byte, key_len)
	hkdfSHA1(bytes, []byte(""), []byte(""), key)
	return
}

func CipherKeySize(method string) uint32 {
	switch method {
	case CIPHER_AES_256_GCM:
		return 32
	case CIPHER_CHACHA20_IETF_POLY1305, CIPHER_XCHACHA20_IETF_POLY1305:
		return chacha20poly1305.KeySize
	default:
		panic("unknow cipher method")
	}
}

func hkdfSHA1(key, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, key, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err) // should never happen
	}
}

type AeadCipher interface {
	Encryptor(salt []byte) (cipher.AEAD, error)
	Decryptor(salt []byte) (cipher.AEAD, error)
}

type cipherChoice struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (c *cipherChoice) Encryptor(salt []byte) (cipher.AEAD, error) {
	skey := make([]byte, len(c.psk))
	hkdfSHA1(c.psk, salt, []byte("ss-subkey"), skey)
	return c.makeAEAD(skey)
}

func (c *cipherChoice) Decryptor(salt []byte) (cipher.AEAD, error) {
	skey := make([]byte, len(c.psk))
	hkdfSHA1(c.psk, salt, []byte("ss-subkey"), skey)
	return c.makeAEAD(skey)
}

func newAES256(psk []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(blk)
}

func NewCipher(method string, psk []byte) (AeadCipher, error) {
	l := len(psk)
	switch method {
	case CIPHER_AES_256_GCM:
		if l != 32 {
			return nil, aes.KeySizeError(l)
		}

		return &cipherChoice{psk: psk, makeAEAD: newAES256}, nil
	case CIPHER_CHACHA20_IETF_POLY1305:
		if l != chacha20poly1305.KeySize {
			return nil, aes.KeySizeError(l)
		}

		return &cipherChoice{psk: psk, makeAEAD: chacha20poly1305.New}, nil
	case CIPHER_XCHACHA20_IETF_POLY1305:
		if l != chacha20poly1305.KeySize {
			return nil, aes.KeySizeError(l)
		}

		return &cipherChoice{psk: psk, makeAEAD: chacha20poly1305.NewX}, nil
	}

	return nil, CipherMethodError(method)
}
