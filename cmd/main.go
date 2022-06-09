package main

import (
	"github.com/is4b3lla3/socks"
	"log"
)

func main() {
	server := socks.SocksServer{
		IP:   "localhost",
		Port: 1099,
	}
	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}
