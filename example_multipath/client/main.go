package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/utils"
	"io"
	"net"
	"os"
	"strings"
)

const message = "foobar"

func getLocalAddresses() []string {
	addresses := make([]string, 0)
	interfaceNet, _ := net.Interfaces()
interfaceLoop:
	for _, currentInterface := range interfaceNet {
		if !strings.Contains(currentInterface.Name, "en") && !strings.Contains(currentInterface.Name, "wlp") {
			continue
		}
		address, err := currentInterface.Addrs()
		if err != nil {
			panic(err)
		}
		for _, a := range address {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				panic(err)
			}
			if utils.IsIPv4(ip) {
				fmt.Println("Added " + ip.String())
				addresses = append(addresses, ip.String())
				continue interfaceLoop
			}
		}
	}
	return addresses
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	err := clientMain()
	if err != nil {
		fmt.Println(err)
		return
	}
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	if len(os.Args) <= 1 {
		return errors.New("no server address given as parameter")
	}
	serverAddress := os.Args[1] + ":1337"
	addresses := getLocalAddresses()
	conn, err := quic.DialAddr(serverAddress, tlsConf, nil, 1)
	if err != nil {
		return err
	}
	for i := 0; i < len(addresses); i++ {
		err = conn.AddPath(addresses[i])
		if err != nil {
			return err
		}
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}

	fmt.Printf("Client: Sending '%s' on %s \n", message, conn.LocalAddr().String())
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	fmt.Printf("Client: Got '%s' from %s \n", buf, conn.RemoteAddr().String())

	return nil
}