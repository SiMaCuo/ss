package main

import (
	"fmt"
	ss "ss-server/shadowsock"
	"ss-server/tcprelay"
)

func main() {
	srv := tcprelay.NewServer("tcp", fmt.Sprintf(":%d", ss.SsConfig.ServerPort), ss.SsConfig.Method, ss.SsConfig.Password)
	if srv == nil {
		return
	}

	srv.Run()
}
