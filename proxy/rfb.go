package proxy

import (
	"crypto/des"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

const (
	rfb3_3 = "RFB 003.003\n"
	rfb3_7 = "RFB 003.007\n"
	rfb3_8 = "RFB 003.008\n"
)

const (
	authInvalid byte = 0
	authNone    byte = 1
	authVNC     byte = 2
)

type rfbProxy struct {
	client connection
	server connection

	logger *logrus.Entry
}

func newRfbProxy(client *websocket.Conn, server net.Conn) rfbProxy {
	return rfbProxy{
		client: wrapWSConnection(client),
		server: wrapTCPConnection(server),

		logger: logrus.New().WithFields(logrus.Fields{
			"client": client.RemoteAddr().String(),
			"server": server.RemoteAddr().String(),
		}),
	}
}

func (p rfbProxy) rfbHandshake(serverPassword string) error {
	// Set up handshake timeouts
	deadline := time.Now().Add(5 * time.Second)
	p.server.setdeadline(deadline)
	p.client.setdeadline(deadline)
	defer p.client.setdeadline(time.Time{})
	defer p.server.setdeadline(time.Time{})

	p.logger.Logger.SetLevel(logrus.DebugLevel)

	rawProtocolVersion, err := p.server.read(12)
	if err != nil {
		return err
	}

	p.logger.Debugf("server protocol: %s", rawProtocolVersion)

	// Check and pass protocol
	switch string(rawProtocolVersion) {
	case rfb3_3, rfb3_7, rfb3_8:
	default:
		rawProtocolVersion = []byte(rfb3_3)
	}

	if err = p.client.write(rawProtocolVersion); err != nil {
		return err
	}

	// Read client protocol
	rawProtocolVersion, err = p.client.read(12)
	if err != nil {
		return err
	}

	p.logger.Debugf("client protocol: %s", rawProtocolVersion)

	var version string
	switch string(rawProtocolVersion) {
	case rfb3_7, rfb3_8:
		version = string(rawProtocolVersion)
	default:
		version = rfb3_3
	}

	// Pass client version
	if err = p.server.write([]byte(version)); err != nil {
		return err
	}

	// Perform security handshake with server
	var secTypes []byte
	switch version {
	case rfb3_3:
		secType, err := p.server.read(4)
		if err != nil {
			return nil
		}
		secTypes = []byte{byte(binary.BigEndian.Uint32(secType))}
	default:
		noOfSecTypes, err := p.server.read(1)
		if err != nil {
			return err
		}
		secTypes, err = p.server.read(int(noOfSecTypes[0]))
		if err != nil {
			return err
		}
	}

	secType := authInvalid
	for _, sec := range secTypes {
		if sec == authNone || (sec == authVNC && serverPassword != "") {
			secType = sec
			break
		}
	}

	p.logger.Debugf("server secTypes=%v, matched=%d", secTypes, secType)

	if secType == authInvalid {
		return fmt.Errorf("No matching authentication type for server")
	}

	switch version {
	case rfb3_3:
	default:
		if err = p.server.write([]byte{secType}); err != nil {
			return err
		}
	}

	if secType == authVNC {
		challenge, err := p.server.read(16)
		if err != nil {
			return err
		}

		response := vncencrypt(serverPassword, challenge)

		if err = p.server.write(response); err != nil {
			return err
		}
	}

	if secType == authVNC || version == rfb3_8 {
		secResult, err := p.server.read(4)
		if err != nil {
			return err
		}

		if binary.BigEndian.Uint32(secResult) == 1 {
			if version == rfb3_8 {
				reasonLength, err := p.server.read(4)
				if err != nil {
					return err
				}
				var reason []byte
				reason, err = p.server.read(int(binary.BigEndian.Uint32(reasonLength)))
				if err != nil {
					return err
				}

				return fmt.Errorf("Server reply: %s", string(reason))
			}

			return fmt.Errorf("VNC Authentication failure")
		}
	}

	// Perform security handshake with client
	switch version {
	case rfb3_3:
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(authNone))
		if err = p.client.write(buf); err != nil {
			return err
		}
	default:
		if err = p.client.write([]byte{1, authNone}); err != nil {
			return err
		}
		secType, err := p.client.read(1)
		if err != nil {
			return err
		}
		if secType[0] != authNone {
			return fmt.Errorf("Client chose unsupported authentication")
		}
	}

	if version == rfb3_8 {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, 0)
		if err = p.client.write(buf); err != nil {
			return err
		}
	}

	p.logger.WithField("version", version).Info("Proxy connection established")

	return nil
}

func (p rfbProxy) shutdown() {
	p.server.close()
	p.client.close()
}

var reverse = [256]byte{
	0, 128, 64, 192, 32, 160, 96, 224,
	16, 144, 80, 208, 48, 176, 112, 240,
	8, 136, 72, 200, 40, 168, 104, 232,
	24, 152, 88, 216, 56, 184, 120, 248,
	4, 132, 68, 196, 36, 164, 100, 228,
	20, 148, 84, 212, 52, 180, 116, 244,
	12, 140, 76, 204, 44, 172, 108, 236,
	28, 156, 92, 220, 60, 188, 124, 252,
	2, 130, 66, 194, 34, 162, 98, 226,
	18, 146, 82, 210, 50, 178, 114, 242,
	10, 138, 74, 202, 42, 170, 106, 234,
	26, 154, 90, 218, 58, 186, 122, 250,
	6, 134, 70, 198, 38, 166, 102, 230,
	22, 150, 86, 214, 54, 182, 118, 246,
	14, 142, 78, 206, 46, 174, 110, 238,
	30, 158, 94, 222, 62, 190, 126, 254,
	1, 129, 65, 193, 33, 161, 97, 225,
	17, 145, 81, 209, 49, 177, 113, 241,
	9, 137, 73, 201, 41, 169, 105, 233,
	25, 153, 89, 217, 57, 185, 121, 249,
	5, 133, 69, 197, 37, 165, 101, 229,
	21, 149, 85, 213, 53, 181, 117, 245,
	13, 141, 77, 205, 45, 173, 109, 237,
	29, 157, 93, 221, 61, 189, 125, 253,
	3, 131, 67, 195, 35, 163, 99, 227,
	19, 147, 83, 211, 51, 179, 115, 243,
	11, 139, 75, 203, 43, 171, 107, 235,
	27, 155, 91, 219, 59, 187, 123, 251,
	7, 135, 71, 199, 39, 167, 103, 231,
	23, 151, 87, 215, 55, 183, 119, 247,
	15, 143, 79, 207, 47, 175, 111, 239,
	31, 159, 95, 223, 63, 191, 127, 255,
}

func vncencrypt(key string, bytes []byte) []byte {
	keyBytes := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	if len(key) > 8 {
		key = key[:8]
	}

	for i := 0; i < len(key); i++ {
		keyBytes[i] = reverse[key[i]]
	}

	block, _ := des.NewCipher(keyBytes)

	result1 := make([]byte, 8)
	block.Encrypt(result1, bytes)
	result2 := make([]byte, 8)
	block.Encrypt(result2, bytes[8:])

	crypted := append(result1, result2...)

	return crypted
}
