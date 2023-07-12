package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/quic-go/quic-go"
	"io"
	"log"
	"math"
	"math/big"
	"os"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	err := echoServer()
	if err != nil {
		panic(err)
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	if len(os.Args) <= 1 {
		return errors.New("no server address given as parameter")
	}
	serverAddress := os.Args[1] + ":1337"

	listener, err := quic.ListenAddr(serverAddress, generateTLSConfig(), nil, 1)
	log.Printf("Start Listening on %s", serverAddress)
	if err != nil {
		return err
	}

	errorChan := make(chan error, 1)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		// for loop AcceptStream
		go func() {
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					errorChan <- err
					break
				}
				log.Printf("Got connection from %s", conn.RemoteAddr())

				buf := make([]byte, math.MaxInt8)
				_, err = readerOutput{stream}.Read(buf)
				if err != nil {
					errorChan <- err
					break
				}
				log.Printf("Server got: %s from %s", string(buf), conn.RemoteAddr().String())

				var outputBuf []byte
				for i := 0; i < len(buf); i++ {
					if buf[i] == 0 {
						break
					} else {
						outputBuf = append(outputBuf, buf[i])
					}
				}

				_, err = stream.Write(outputBuf)
				if err != nil {
					errorChan <- err
					break
				}

				log.Printf("Send: '%s' to %s", string(outputBuf), conn.RemoteAddr())
				err = stream.Close()
				if err != nil {
					errorChan <- err
					break
				}}
		}()
		select {
		case sendError := <- errorChan:
			log.Printf(sendError.Error())
			break
		default:
			continue
		}
	}
}

// Reader for output of content of stream
type readerOutput struct{ io.Reader }

func (r readerOutput) Read(b []byte) (int, error) {
	return r.Reader.Read(b)
}

// Set up a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
