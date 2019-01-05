package main

import (
	"fmt"
	ss "ss-server/shadowsock"
)

func main() {
	srv := ss.NewServer("tcp", fmt.Sprintf(":%d", ss.SsConfig.ServerPort))
	if srv == nil {
		return
	}

	srv.Run()
}
