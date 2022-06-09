package socks

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClinetAuthMessage(t *testing.T) {
	t.Run("should generate a message", func(t *testing.T) {
		b := []byte{SOCKSVersion, 2, 0x00, 0x01}
		reader := bytes.NewReader(b)

		message, err := NewClientAuthMessage(reader)
		if err != nil {
			t.Fatalf("test failed")
		}
		if message.Version != SOCKSVersion {
			t.Fatalf("test failed: socks version is invalid")
		}
		if message.Nmethods != 2 {
			t.Fatalf("teet failed")
		}
		if reflect.DeepEqual(message.Methods, []byte{0x01, 0x02}) {
			t.Fatalf("teet failed")
		}
	})

}
func TestNewServerAuthMessage(t *testing.T) {
	t.Run("shoould pass", func(t *testing.T) {
		var buf bytes.Buffer
		err := NewServerAuthMessage(&buf, MethodNoAuth)
		if err != nil {
			t.Fatalf("should get nil but got %s", err)
		}
		got := buf.Bytes()
		if !reflect.DeepEqual(got, []byte{SOCKSVersion, MethodNoAuth}) {
			t.Fatalf("should send %v but send %v", []byte{SOCKSVersion, MethodNoAuth}, got)
		}
	})
}
