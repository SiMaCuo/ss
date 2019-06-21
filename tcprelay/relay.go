package tcprelay

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"ss-server/crypto"
	"ss-server/shadowsock"
)

var log = shadowsock.Log

const (
	idxAtyp     = 3
	idxIpv4     = idxAtyp + 1
	idxIpv4Port = net.IPv4len + idxIpv4
	idxIpv6     = idxAtyp + 1
	idxIpv6Port = net.IPv6len + idxIpv6
	idxDmLen    = idxAtyp + 1

	lenIpv4 = net.IPv4len + 2
	lenIpv6 = net.IPv6len + 2

	atypV4   = 1
	atypV6   = 4
	atypDm   = 3
	atypMask = 0xf
)

type Server struct {
	l      net.Listener
	cipher crypto.AeadCipher
}

func NewServer(network, addr, cipherMethod, password string) *Server {
	l, err := net.Listen(network, addr)
	if err != nil {
		log.Debugf("listen on %s failed, %s", addr, err)

		return nil
	}

	log.Info("``````````````````````````````````````````````````````````")
	log.Info("listen on ", addr)
	fmt.Printf("listen on: %s\n", addr)

	cipher, err := crypto.NewCipher(cipherMethod, []byte(password))
	if err != nil {
		log.Info("new cipher failed %s", err.Error())
		l.Close()
		return nil
	}

	return &Server{
		l:      l,
		cipher: cipher,
	}
}

func (s *Server) accept() (c net.Conn, err error) {
	c, err = s.l.Accept()
	return
}

func (s *Server) Run() {
	for {
		c, err := s.accept()
		if err != nil {
			log.Info("accpet error: %v", err)

			continue
		}

		go s.handleConnection(c)
	}
}

var zeroNonce = make([]byte, 64)

type res struct {
	amt int64
	err error
}

func (s *Server) handShake(c net.Conn, resChan chan<- res) (net.Conn, *AeadDecryptor, string, error) {
	salt, saltSize := make([]byte, s.cipher.SaltSize()), s.cipher.SaltSize()
	n, err := c.Read(salt)
	if err != nil {
		msg := fmt.Errorf("recv salt faile %s", err.Error())
		return nil, nil, "", msg
	}

	if n != saltSize {
		msg := fmt.Errorf("want %d byte salt, byte recv %d byte", saltSize, n)
		return nil, nil, "", msg
	}

	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	aead, err := s.cipher.Decryptor(salt)
	if err != nil {
		msg := fmt.Errorf("create decryptor failed %s", err.Error())
		return nil, nil, "", msg
	}

	decr := NewAeadDecryptor(c, aead, resChan)
	n, err = decr.Read(buf)
	if err != nil {
		msg := fmt.Errorf("decrypt handshake message failed")
		return nil, nil, "", msg
	}

	host, err := parseRequest(buf[:n])
	if err != nil {
		return nil, nil, "", err
	}

	if strings.ContainsRune(host, 0x0) {
		msg := fmt.Errorf("host contains illegal characters")
		return nil, nil, "", msg
	}

	decr.setName(fmt.Sprintf("%s <- %s", host, c.RemoteAddr().String()))
	log.Debug(fmt.Sprintf("%s <- %s connect", host, c.RemoteAddr().String()))
	conn, err := net.Dial("tcp", host)
	if err != nil {
		msg := fmt.Errorf("connect to host %s failed %s", host, err.Error())
		return nil, nil, "", msg
	}

	return conn, decr, host, nil
}

func (s *Server) genSaltAndSend(c net.Conn) ([]byte, error) {
	salt := make([]byte, s.cipher.SaltSize())
	io.ReadFull(rand.Reader, salt)
	n, err := c.Write(salt)
	if err != nil {
		return nil, err
	}
	if n != len(salt) {
		return nil, fmt.Errorf("salt %d byte, but send %d byte", len(salt), n)
	}

	return salt, nil
}

func (s *Server) handleConnection(client net.Conn) {
	salt, err := s.genSaltAndSend(client)
	if err != nil {
		log.Debug("gen salt failed: ", err)
		client.Close()
		return
	}

	c2wRes := make(chan res, 1)
	web, src, host, err := s.handShake(client, c2wRes)
	if err != nil {
		log.Debug("handshake failed: ", err)
		client.Close()
		return
	}

	thisName := fmt.Sprintf("%s <-> %s", host, client.RemoteAddr().String())
	go func() {
		io.Copy(web, src)
		client.Close()
	}()

	w2cRes := make(chan res, 1)
	aead, _ := s.cipher.Encryptor(salt)
	dst := NewAeadEncryptor(client, aead, w2cRes)
	dst.setName(fmt.Sprintf("%s -> %s", host, client.RemoteAddr().String()))
	go func() {
		io.Copy(dst, web)
		web.Close()
	}()

	var finalWait chan res
	select {
	// client read closed
	case <-c2wRes:
		finalWait = w2cRes
	// web read closed
	case <-w2cRes:
		finalWait = c2wRes
	}

	<-finalWait
	log.Debugf("%s total done", thisName)
}

func Stat(c2w, w2c int64) {}

func SetReadDeadLine(c net.Conn, scale int) {
	c.SetReadDeadline(time.Now().Add(time.Duration(shadowsock.SsConfig.ReadTimeout * scale) * time.Second))
}

func parseRequest(buf []byte) (host string, err error) {
	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 0x5 {
		err = fmt.Errorf("only support version 5, but %d", ver)
		return
	}

	if cmd != 0x1 {
		err = fmt.Errorf("only support connect command, buf %d", cmd)
		return
	}

	var rdStart, rdEnd int
	switch atyp & atypMask {
	case atypV4:
		rdStart, rdEnd = idxIpv4, idxIpv4+lenIpv4

	case atypV6:
		rdStart, rdEnd = idxIpv6, idxIpv6+lenIpv6

	case atypDm:
		rdStart, rdEnd = idxDmLen+1, idxDmLen+1+int(buf[idxDmLen])+2

	default:
		err = fmt.Errorf("address type not supported: %d, %v", atyp, buf)
	}

	if err != nil {
		return
	}

	switch atyp & atypMask {
	case atypV4, atypV6:
		host = net.IP(buf[rdStart : rdEnd-2]).String()

	case atypDm:
		host = string(buf[rdStart : rdEnd-2])
	}

	port := binary.BigEndian.Uint16(buf[rdEnd-2 : rdEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}
