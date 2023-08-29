package main

import (
	"encoding/base64"
	"net/http"
	"crypto/tls"

	"github.com/namsral/flag"
	"github.com/rkojedzinszky/go-novncauthproxy/proxy"
	"github.com/rkojedzinszky/go-novncauthproxy/token"
	"github.com/sirupsen/logrus"
)

func main() {
	listen := flag.String("listen", ":8080", "Listen address")
	jweSecret := flag.String("jwe-secret", "", "Secret used for encrypting JWEs")
	keyFile := flag.String("keyfile", "", "TLS key file in PEM format")
	certFile := flag.String("certfile", "", "TLS certificate file in PEM format")
	plain := flag.Bool("plain", false, "Use plain URI parser. Not for production use!")
	uri := flag.String("uri", "/novnc/", "Base URI for handling WS requests")
	logLevel := flag.Int("log-level", int(logrus.InfoLevel), "Logging level")

	flag.String(flag.DefaultConfigFlagname, "", "path to config file")
	flag.Parse()

	logrus.SetLevel(logrus.Level(*logLevel))

	var tlsConfig *tls.Config
	if *keyFile != "" && *certFile == "" {
		logrus.Fatal("TLS key file without certificate file specified")
	} else if *keyFile == "" && *certFile != "" {
		logrus.Fatal("TLS certificate file without key file specified")
	} else if *keyFile != "" && *certFile != "" {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			PreferServerCipherSuites: true,
		}
	}

	var parser token.Parser
	if *plain {
		parser = token.NewPlainParser()
	} else if *jweSecret == "" {
		logrus.Fatal("Must specify JWE key")
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

	mux := http.NewServeMux()
	mux.Handle(*uri, p)

	srv := &http.Server{
		Addr: *listen,
		Handler: mux,
		TLSConfig: tlsConfig,
	}

	if tlsConfig != nil {
		logrus.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
	} else {
		logrus.Fatal(srv.ListenAndServe())
	}
}
