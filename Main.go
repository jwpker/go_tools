package main

import (
	"github.com/jwpker/go_tools/net/socks5"
)

func main() {
	server, err := socks5.New("212.71.237.14", 9527)
	if err != nil {
		return
	}
	server.ListenAndServer()
}
