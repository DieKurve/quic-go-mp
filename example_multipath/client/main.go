package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/utils"
	"io"
	"log"
	"math"
	"net"
	"os"
	"strings"
	"time"
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
		for _, currentAddress := range address {
			ip, _, err := net.ParseCIDR(currentAddress.String())
			if err != nil {
				panic(err)
			}
			if utils.IsIPv4(ip) {
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
	if len(addresses) > 1 {
		for i := 0; i < len(addresses); i++ {
			err = conn.AddPath(addresses[i])
			if err != nil {
				return err
			}
		}
	} else {
		err = conn.AddPath(addresses[0])
		if err != nil {
			return err
		}
	}

	paths := conn.GetPaths()
	for _, path := range paths {
		log.Printf("Open stream on path %s\n", path.GetPathID())
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := path.OpenStreamSync(ctx)
		if err != nil {
			return err
		}

		log.Printf("Sending '%s' on %s \n", message, path.LocalAddr().String())
		_, err = stream.Write([]byte(message))
		if err != nil {
			return err
		}

		buf := make([]byte, math.MaxInt8)
		_, err = io.ReadAtLeast(stream, buf, 1)
		if err != nil {
			return err
		}

		log.Printf("Got '%s' from %s\n", buf, path.RemoteAddr().String())
		if err != nil {
			return err
		}

		err = stream.Close()
		if err != nil {
			return err
		}

	}
	return nil
}
