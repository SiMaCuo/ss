package main

import (
	ss "ss-server/shadowsock"
)

func main() {
	srv := ss.NewServer("tcp", ":18129")
	if srv == nil {
		return
	}

	srv.Run()
}
