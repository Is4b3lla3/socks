package socks

import (
	"errors"
	"io"
)

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)
const (
	PasswordMethodVerion = 0x01
	PasswordAuthSucces   = 0x00
	PasswordAuthFailure  = 0x11
)

type ClientAuthMessage struct {
	Version  byte
	Nmethods byte
	Methods  []Method
}

type ClientPasswordMessage struct {
	Username string
	Password string
}

type Method = byte

var (
	ErrorPasswordAuthFailure   = errors.New("Error Auth Password")
	ErrorPasswordCheckerNotSet = errors.New("error Password checker not set")
)

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

func NewClientPasswordMessage(conn io.Reader) (*ClientPasswordMessage, error) {
	// read version and username length
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	version, uernameLen := buf[0], buf[1]
	if version != PasswordMethodVerion {
		return nil, ErrorCommandNotSupported
	}
	//read username and passwordlenth
	buf = make([]byte, uernameLen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	username, passwordLenth := string(buf[:len(buf)-1]), buf[len(buf)-1]

	// read password
	if len(buf) < int(passwordLenth) {
		buf = make([]byte, passwordLenth)
	}
	if _, err := io.ReadFull(conn, buf[:passwordLenth]); err != nil {
		return nil, err
	}
	return &ClientPasswordMessage{
		Username: username,
		Password: string(buf[:passwordLenth]),
	}, nil
}
func WriteServerPasswordMessage(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{PasswordMethodVerion, status})
	return err
}
