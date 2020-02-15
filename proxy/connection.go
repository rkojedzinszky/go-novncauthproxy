package proxy

import (
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type connection interface {
	// Read exactly n bytes of data, return error if failed
	read(n int) ([]byte, error)
	// Receive data, return on error
	receive() ([]byte, error)
	// Write len(buf) bytes data, return error if failed
	write(buf []byte) error
	// close the connection
	close() error
	// setdeadline
	setdeadline(t time.Time) error
}

const tcpBufsize = 16 << 10

// Wraps a tcpConnection
type tcpConnection struct {
	conn    net.Conn
	readbuf []byte
}

func wrapTCPConnection(conn net.Conn) connection {
	return tcpConnection{
		conn:    conn,
		readbuf: make([]byte, tcpBufsize),
	}
}

// Wraps a websocket connection
type wsConnection struct {
	conn *websocket.Conn
}

func wrapWSConnection(conn *websocket.Conn) connection {
	return wsConnection{
		conn: conn,
	}
}

// tcpConnection
func (c tcpConnection) read(n int) ([]byte, error) {
	read, err := c.conn.Read(c.readbuf[:n])
	if err != nil {
		return nil, err
	}

	if read != n {
		return nil, fmt.Errorf("tcpConnection.read: got %d bytes, expected: %d", read, n)
	}

	return c.readbuf[:n], nil
}

func (c tcpConnection) receive() ([]byte, error) {
	read, err := c.conn.Read(c.readbuf[:tcpBufsize])
	if err != nil {
		return nil, err
	}

	return c.readbuf[:read], nil
}

func (c tcpConnection) write(buf []byte) error {
	written, err := c.conn.Write(buf)
	if err != nil {
		return err
	}

	if written != len(buf) {
		return fmt.Errorf("tcpConnection.write: written %d bytes, wanted %d", written, len(buf))
	}

	return nil
}

func (c tcpConnection) close() error {
	return c.conn.Close()
}

func (c tcpConnection) setdeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// wsConnection
func (c wsConnection) read(n int) ([]byte, error) {
	msg, err := c.receive()
	if err != nil {
		return nil, err
	}

	if len(msg) != n {
		return nil, fmt.Errorf("wsConnection.read: read %d bytes, expected %d", len(msg), n)
	}

	return msg, nil
}

func (c wsConnection) receive() ([]byte, error) {
	typ, msg, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if typ != websocket.BinaryMessage {
		return nil, fmt.Errorf("wsConnection.receive: non-binary message received")
	}

	return msg, nil
}
func (c wsConnection) write(buf []byte) error {
	return c.conn.WriteMessage(websocket.BinaryMessage, buf)
}

func (c wsConnection) close() error {
	return c.conn.Close()
}

func (c wsConnection) setdeadline(t time.Time) error {
	return c.conn.UnderlyingConn().SetDeadline(t)
}
