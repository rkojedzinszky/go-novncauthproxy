package main

import (
	"encoding/base64"
	"net/http"

	"github.com/namsral/flag"
	"github.com/rkojedzinszky/go-novncauthproxy/proxy"
	"github.com/rkojedzinszky/go-novncauthproxy/token"
	"github.com/sirupsen/logrus"
)

func main() {
	listen := flag.String("listen", ":8080", "Listen address")
	jweSecret := flag.String("jwe-secret", "", "Secret used for encrypting JWEs")
	plain := flag.Bool("plain", false, "Use plain URI parser. Not for production use!")
	uri := flag.String("uri", "/novnc/", "Base URI for handling WS requests")
	logLevel := flag.Int("log-level", int(logrus.InfoLevel), "Logging level")

	flag.Parse()

	logrus.SetLevel(logrus.Level(*logLevel))

	var parser token.Parser
	if *plain {
		parser = token.NewPlainParser()
	} else if *jweSecret == "" {
		logrus.Fatal("Must specify key")
	} else {
		skey, err := base64.StdEncoding.DecodeString(*jweSecret)
		if err != nil {
			logrus.Fatal(err)
		}
		parser, err = token.NewJWEParser(skey)
		if err != nil {
			logrus.Fatal(err)
		}
	}

	p := proxy.NewProxy(parser)

	http.Handle(*uri, p)
	http.ListenAndServe(*listen, nil)
}
