package main

import (
	"flag"
	"github.com/is4b3lla3/socks"
	"log"
)

func main() {
	ip := flag.String("ip", "127.0.0.1", "请输入监听地址")
	port := flag.Int("port", 1089, "请输入端口号")
	username := flag.String("username", "", "用户名")
	password := flag.String("password", "", "密码")
	flag.Parse()

	//
	users := map[string]string{
		*username: *password,
	}
	authserver := socks.SocksServer{
		IP:       *ip,
		Port:     *port,
		Username: *username,
		Password: *password,
		Config: &socks.Config{
			AuthMethod: socks.MethodPassword,
			PasswordChecker: func(username, password string) bool {
				wantPassword, ok := users[username]
				if !ok {
					return false
				}
				return wantPassword == password
			},
		},
	}
	server := socks.SocksServer{
		IP:   *ip,
		Port: *port,
		Config: &socks.Config{
			AuthMethod: socks.MethodNoAuth,
		},
	}
	log.Println("Usage: ./socks -ip=192.168.3.1 -port=1080")
	log.Printf("Socks5Server is run on %s:%d", server.IP, server.Port)
	if len(*username) == 0 {
		err := server.Run()
		if err != nil {
			log.Fatal(err)
		}
	}
	err := authserver.Run()
	if err != nil {
		log.Fatal(err)
	}
}
