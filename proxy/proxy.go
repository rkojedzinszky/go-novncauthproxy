package proxy

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rkojedzinszky/go-novncauthproxy/token"
	"github.com/sirupsen/logrus"
)

// Proxy represents a VNC proxy instance
type Proxy struct {
	parser token.Parser
}

// NewProxy creates a new Proxy instance
func NewProxy(parser token.Parser) Proxy {
	return Proxy{
		parser: parser,
	}
}

var wsUpgrader = websocket.Upgrader{
	HandshakeTimeout: 5 * time.Second,
	ReadBufferSize:   64 << 10,
	WriteBufferSize:  64 << 10,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	Subprotocols: []string{"binary"},
}

var tcpDialer = net.Dialer{
	Timeout: 5 * time.Second,
}

func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, err := p.parser.ExtractControlRequest(r)
	if err != nil {
		logrus.Warn(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	logrus.Debug(r.RemoteAddr, ": received token:", token)

	clientConn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		logrus.Error("Failed to upgrade to websocket: ", err)
		return
	}

	serverConn, err := tcpDialer.Dial("tcp", token.Destination)
	if err != nil {
		logrus.Error("Failed to connect to server: ", err)
		clientConn.Close()
		return
	}

	cl := newRfbProxy(clientConn, serverConn)

	if err = cl.rfbHandshake(token.Password); err != nil {
		cl.shutdown()
		cl.logger.Error(err)

		return
	}

	go cl.run()
}

func (p rfbProxy) forward(ctx context.Context, from, to connection) {
	for {
		buf, err := from.receive()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
					p.logger.Info("Client closed connection")
				} else {
					p.logger.Warn(err)
				}
			}

			return
		}

		if err = to.write(buf); err != nil {
			p.logger.Warn(err)

			return
		}
	}
}

func (p rfbProxy) run() {
	defer p.shutdown()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		p.forward(ctx, p.client, p.server)
		cancel()
	}()

	go func() {
		p.forward(ctx, p.server, p.client)
		cancel()
	}()

	<-ctx.Done()
}
