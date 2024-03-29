package socks

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

type Server interface {
	//run socks5 server
	Run() error
}

//实现socks5 server
type SocksServer struct {
	IP       string
	Port     int
	Username string
	Password string
	Config   *Config
}
type Config struct {
	AuthMethod      Method
	PasswordChecker func(Username string, Password string) bool
}

const SOCKSVersion = 0x05
const ReservedField = 0x00

var (
	ErrorVersionNotSupported       = errors.New("protocol version not supported")
	ErrorMethodVersionNotSupported = errors.New("sub-negotiation method version not supported")
	ErrorCommandNotSupported       = errors.New("Command not supported")
	ErrorInvalidReservedField      = errors.New("InvalidReservedField!")
	ErrorAddressNotSupported       = errors.New("address not supported")
	ErrorAddressTypeNotSupported   = errors.New("addresstype not supported,only support ipv4")
)

func ServerConfig(config *Config) error {
	// 初始化server 配置
	if config.AuthMethod == MethodPassword && config.PasswordChecker == nil {
		return ErrorPasswordCheckerNotSet
	}
	return nil
}

//实现Server接口
func (s *SocksServer) Run() error {
	if len(s.Username) != 0 {
		// 密码认证开启
		if err := ServerConfig(s.Config); err != nil {
			return err
		}
	}

	//循环处理客户端请求
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	//监听 lcalhost:1080
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		/**
		  这里的请求是三次握手accept从listener的已经三次握手的队列中取出一个TCP连接
		*/
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Connect falied from %s: %s", conn.RemoteAddr(), err)
			continue
		}
		//已经正确获取到连接
		// 携程调用handleconnect函数无法捕获error，嵌套个匿名函数处理
		go func() {
			defer conn.Close()
			err := handleConnection(conn, s.Config)
			if err != nil {
				log.Printf("handle connection failed from  %s: %s", conn.RemoteAddr(), err)
			}
		}()

	}
}

//handle request
func handleConnection(conn net.Conn, config *Config) error {
	// 协商
	if err := auth(conn, config); err != nil {
		return err
	}
	// 请求
	targetConn, err := request(conn)
	if err != nil {
		return err
	}

	// 转发
	return forward(conn, targetConn)

}

//协商函数
func auth(conn io.ReadWriter, config *Config) error {
	//read clinet auth message
	clientmessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}
	//遍历auth method 是否支持
	var acceptable bool
	for _, method := range clientmessage.Methods {
		if method == config.AuthMethod {
			acceptable = true
		}

	}
	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not support")
	}
	//
	if err := NewServerAuthMessage(conn, config.AuthMethod); err != nil {
		return err
	}
	// password 认证
	if config.AuthMethod == MethodPassword {
		message, err := NewClientPasswordMessage(conn)
		if err != nil {
			return nil
		}
		if !config.PasswordChecker(message.Username, message.Password) {
			//认证失败
			WriteServerPasswordMessage(conn, PasswordAuthFailure)
			return ErrorPasswordAuthFailure
		}
		//认证成功
		if err := WriteServerPasswordMessage(conn, PasswordAuthSucces); err != nil {
			return err
		}

	}
	return nil
}

//服务端读取客户端请求函数
func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	message, err := NewClinetRequestMessage(conn)
	if err != nil {
		return nil, err
	}
	//判断是否支持cmd 只支持TCP（connect）
	if message.Cmd != CmdConnect {
		return nil, WriteRequesFailureMessage(conn, ReplyCommandNotSupported)
	}
	//判断地址
	if message.AddrType == IPV6Length {
		return nil, WriteRequesFailureMessage(conn, ReplyAddressTyeNotSupported)
	}
	//command和addrtype都支持
	// 开始请求访问目标服务 socks可代理任意tcp流量
	address := fmt.Sprintf("%s:%d", message.Address, message.Port)
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		//返回错误信息，这里没有针对性的返回相应的reply，统一写成了拒绝
		return nil, WriteRequesFailureMessage(conn, ReplyConnectionRefuesd)
	}
	// local addr & port
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr)
	//与目标网站连接成功后，返回给客户端连接信息
	// Send Success reply
	return targetConn, WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port))

	return nil, nil
}

//转发函数（TCP）
// 2个 conn 一个client与socksserver 一个socksserver与 target
func forward(conn io.ReadWriter, targetConn io.ReadWriteCloser) error {
	defer targetConn.Close()
	var err error
	go io.Copy(targetConn, conn)
	_, err = io.Copy(conn, targetConn)
	return err
}
