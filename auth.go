package socks

import (
	"io"
)

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)

type ClientAuthMessage struct {
	Version  byte
	Nmethods byte
	Methods  []Method
}
type Method = byte

//从一个tcp流中读取报文产生ClinetAuthMessage对象
func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	//读取version
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	//判断版本是否合法
	if buf[0] != SOCKSVersion {
		return nil, ErrorVersionNotSupported
	}
 
	//读取nmethods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version: SOCKSVersion, Nmethods: nmethods, Methods: buf,
	}, nil
}

func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKSVersion, method}
	_, err := conn.Write(buf)
	return err

}
