package main

import (
	"net"
)

func main() {
	l, err := net.Listen("tcp", ":11229")
	if err != nil {
		log.Debug("listen on :11229 failed, %s", err.Error())

		return
	}
}
