package shadowsocks

import (
	"net"
	"time"
	"io"
	"fmt"
	"encoding/binary"
	"strconv"
)

const (
	idxAtyp = 0
	idxIpv4 = 1
	idxIpv4Port = net.IPv4len + idxIpv4
	idxIpv6 = 1
	idxIpv6Port = net.IPv6len + idxIpv6
	idxDmLen = 1

	lenIpv4 = net.IPv4len + 2
	lenIpv6 = net.IPv6len + 2

	atypV4 = 1
	atypV6 = 4
	atypDm = 3
	atypMask = 0xf
)


type Server struct {
	l *net.Listener
}

func NewServer(net, addr string) *Server {
	l, err := net.Listen(net, addr)
	if err != nil {
		log.Debug("listen on %s failed, %s", addr, err.Error())

		return nil
	}

	return &Server {
		l = &l
	}
}

func (s *Server) accept() (c net.Conn, err error) {
	c, err = s.Accept()
}

func (s *Server) Run() {
	for {
		c, err := s.accept()
		if err != nil {
			log.Info("accpet error: %v", err)

			continue
		}
		
		go handleConnection(c)
	}
}

func SetReadDeadLine(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(10*time.Seconds))
}

func parseRequest(c net.Conn) (host string, err error) {
	SetReadDeadLine(c)

	buf := make([]byte, 269)
    host = ""
	if _, err = io.ReadFull(c, buf[:idxAtyp+1]); err != nil {
		return
	}
	
	var rdStart, rdEnd int
	atyp := buf[idxAtyp]
	switch atyp & atypMask {
	case atypV4:
		rdStart, rdEnd = idxIpv4, idxIpv4 + lenIpv4
		
	case atypv6:
		rdStart, rdEnd = idxIpv6, idxIpv6 + lenIpv6

	case atypDm:
		if _, err = io.ReadFull(c, buf[idxDmLen:idxDmLen+1]); err != nil {
			return
		}
		rdStart, rdEnd = idxDmLen+1, idxDmLen+1+buf[idxDmLen]+2

	default:
		err = fmt.Errorf("address type not supported: %d", atyp)
	}

	if _, err = io.ReadFull(c, buf[rdStart:rdEnd]); err != nil {
		return
	}

	switch atyp & atypMask {
	case atypV4, atypV6:
		host = net.IP(buf[rdStart:rdEnd]).String()

	case atypDm:
		host = string(buf[rdStart:rdEnd])
	}

	port := binary.BigEndian.Uint16(buf[rdEnd-2:rdEnd])
	host = net.JoinHostPort(host, strconv.Itoa(port))

	return
}









	

func handleConnection(c net.Conn) {
}


	

