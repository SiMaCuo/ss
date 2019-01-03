package shadowsocks

import (
	"net"
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

func handleConnection(c net.Conn) {
}


	

