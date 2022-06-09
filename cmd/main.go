package main

import (
	"flag"
	"github.com/is4b3lla3/socks"
	"log"
)

func main() {
	ip := flag.String("ip", "127.0.0.1", "请输入监听地址")
	port := flag.Int("port", 1090, "请输入端口号")
	flag.Parse()

	server := socks.SocksServer{
		IP:   *ip,
		Port: *port,
	}
	log.Println("Usage: ./socks -ip=192.168.3.1 -port=1080")
	log.Printf("Socks5Server is runs on %s:%d", server.IP, server.Port)
	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}
