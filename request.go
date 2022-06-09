package socks

import (
	"io"
	"log"
	"net"
)

type ClinetRequestMessage struct {
	//Version byte
	Cmd      Command
	Address  string
	AddrType AddressType
	Port     uint16
}
type Command = byte

const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03
)

type AddressType = byte

const (
	TypeIPV4   AddressType = 0x01
	TypeDomain AddressType = 0x03
	TypeIPV6   AddressType = 0x04
)
const (
	IPV4Length = 4
	IPV6Length = 16
	PortLength = 2
)

type ReplyType = byte

const (
	ReplySuccess ReplyType = iota
	ReplyServerFailure
	ReplyConnectionNotAllowed
	ReplyNetWorkUnreachable
	ReplyHostUnreachable
	ReplyConnectionRefuesd
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTyeNotSupported
)

func NewClinetRequestMessage(conn io.Reader) (*ClinetRequestMessage, error) {
	buf := make([]byte, IPV4Length)
	//read version,command,reserved,addresstype
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	version, command, reserved, addresstype := buf[0], buf[1], buf[2], buf[3]
	if version != SOCKSVersion {
		return nil, ErrorVersionNotSupported
	}
	if command != CmdConnect && command != CmdBind && command != CmdUDP {
		return nil, ErrorCommandNotSupported
	}
	if reserved != ReservedField {
		return nil, ErrorInvalidReservedField
	}
	if addresstype != TypeIPV4 && addresstype != TypeDomain && addresstype != TypeIPV6 {
		return nil, ErrorAddressNotSupported
	}
	//代码运行到这里，4个字段是有效的
	//--------------------------
	//read address and port
	message := ClinetRequestMessage{
		Cmd:      command,
		AddrType: addresstype}

	switch addresstype {
	case TypeIPV6:
		buf = make([]byte, IPV6Length)
		fallthrough
	case TypeIPV4:

		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf)
		message.Address = ip.String()
	case TypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		domainLength := buf[0]
		if domainLength > IPV4Length {
			buf = make([]byte, domainLength)
		}
		if _, err := io.ReadFull(conn, buf[:domainLength]); err != nil {
			return nil, err
		}
		buff := buf[:domainLength]
		message.Address = string(buff)
	}
	//读取port
	if _, err := io.ReadFull(conn, buf[:PortLength]); err != nil {
		return nil, err
	}
	message.Port = uint16(buf[0])<<8 + uint16(buf[1])
	log.Println(message)
	return &message, nil
}

//请求成功发送函数
func WriteRequestSuccessMessage(conn io.Writer, ip net.IP, port uint16) error {
	addressType := TypeIPV4
	if len(ip) == IPV6Length {
		addressType = TypeIPV6
	}
	//write version,reply sucess,reserved,addresstype
	_, err := conn.Write([]byte{SOCKSVersion, ReplySuccess, ReservedField, addressType})
	if err != nil {
		return err
	}
	//weite bind ip
	if _, err := conn.Write(ip); err != nil {
		return err
	}
	//write bind port
	buf := make([]byte, 2)
	buf[0] = byte(port >> 8)
	buf[1] = byte(port - uint16(buf[0]<<8))
	_, err = conn.Write(buf)
	return err
}
func WriteRequesFailureMessage(conn io.Writer, replyType ReplyType) error {
	_, err := conn.Write([]byte{SOCKSVersion, replyType, ReservedField, TypeIPV4, 0, 0, 0, 0, 0, 0})
	return err
}
