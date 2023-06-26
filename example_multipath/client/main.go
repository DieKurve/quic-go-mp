package main

import (
  "context"
  "crypto/rand"
  "crypto/rsa"
  "crypto/tls"
  "crypto/x509"
  "encoding/pem"
  "fmt"
  "github.com/quic-go/quic-go"
  "github.com/quic-go/quic-go/internal/utils"
  "io"
  "math/big"
  "net"
  "strings"
)

const message = "foobar"

func getAddresses() []string{
  addresses := make([]string, 0)
  interfaceNet, _ := net.Interfaces()
  interfaceLoop:
  for _, currentInterface := range interfaceNet {
    if !strings.Contains(currentInterface.Name, "enp") {
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
      if utils.IsIPv4(ip){
        utils.DefaultLogger.Infof("Added %s Address", ip.String())
        addresses = append(addresses, ip.String()+":10033")
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
    panic(err)
  }
}


func clientMain() error {
  tlsConf := &tls.Config{
    InsecureSkipVerify: true,
    NextProtos:         []string{"quic-echo-example"},
  }
  addresses := getAddresses()
  conn, err := quic.DialAddr(addresses[0], tlsConf, nil, 1)
  if err != nil {
    return err
  }

  for i := 1; i < len(addresses); i++ {
    err = conn.AddPath(addresses[i])
    if err != nil {
      return err
    }
  }

  stream, err := conn.OpenStreamSync(context.Background())
  if err != nil {
    return err
  }

  fmt.Printf("Client: Sending '%s'\n", message)
  _, err = stream.Write([]byte(message))
  if err != nil {
    return err
  }

  buf := make([]byte, len(message))
  _, err = io.ReadFull(stream, buf)
  if err != nil {
    return err
  }
  fmt.Printf("Client: Got '%s'\n", buf)

  return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
  fmt.Printf("Server: Got '%s'\n", string(b))
  return w.Writer.Write(b)
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