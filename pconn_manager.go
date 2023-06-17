package quic

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	// reuse "github.com/jbenet/go-reuseport"
)

type receivedRawPacket struct {
	rcvPconn   net.PacketConn
	remoteAddr net.Addr
	data       []byte
	rcvTime    time.Time
}

type pconnManager struct {
	// Two kinds of PacketConn: on specific unicast address and the "primary"
	// listening on any
	mutex    sync.Mutex
	pconns   map[string]net.PacketConn
	pconnAny net.PacketConn

	localAddrs []net.UDPAddr

	perspective protocol.Perspective

	rcvRawPackets chan *receivedRawPacket

	changePaths chan struct{}
	closeConns  chan struct{}
	closed      chan struct{}
	errorConn   chan error
	timer       *time.Timer
}

// Set up the pconn_manager and the pconnAny connection
func (pcm *pconnManager) setup(pconnArg net.PacketConn, listenAddr net.Addr) error {
	pcm.pconns = make(map[string]net.PacketConn)
	pcm.localAddrs = make([]net.UDPAddr, 0)
	pcm.rcvRawPackets = make(chan *receivedRawPacket)
	pcm.changePaths = make(chan struct{}, 1)
	pcm.closeConns = make(chan struct{}, 1)
	pcm.closed = make(chan struct{}, 1)
	pcm.errorConn = make(chan error, 1) // Made non-blocking for tests
	pcm.timer = time.NewTimer(0)

	if pconnArg == nil {
		pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			utils.DefaultLogger.Errorf("pconn_manager: %v", err)
			// Format for expected consistency
			operr := &net.OpError{Op: "listen", Net: "udp", Source: listenAddr, Addr: listenAddr, Err: err}
			return operr
		}
		pcm.pconnAny = pconn
	} else {
		// FIXME Update localAddrs
		pcm.pconnAny = pconnArg
	}

	if utils.DefaultLogger.Debug() {
		utils.DefaultLogger.Debugf("Created pconn_manager, any on %s", pcm.pconnAny.LocalAddr().String())
	}

	// Run the pconnManager
	go pcm.run()

	return nil
}

func (pcm *pconnManager) listen(pconn net.PacketConn) {
	var err error

listenLoop:
	for {
		var n int
		var addr net.Addr
		data := getPacketBuffer().Data
		data = data[:protocol.MaxPacketBufferSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncate packet, which will then end up undecryptable
		n, addr, err = pconn.ReadFrom(data)
		if err != nil {
			// XXX (QDC): as soon as a path failed, kill the connection.
			// TODO (QDC): be more resilient in the future without breaking expectations
			select {
			case pcm.errorConn <- err:
			default:
				// Don't block
			}
			break listenLoop
		}
		data = data[:n]

		rcvRawPacket := &receivedRawPacket{
			rcvPconn:   pconn,
			remoteAddr: addr,
			data:       data,
			rcvTime:    time.Now(),
		}

		pcm.rcvRawPackets <- rcvRawPacket
	}
}

func (pcm *pconnManager) run() {
	// First start to listen to the sockets
	go pcm.listen(pcm.pconnAny)
	// XXX (QDC): maybe wait for one handshake to complete, but maybe not needed
	// FIXME Server starting on any vs. server with non-any address
	if pcm.perspective == protocol.PerspectiveClient {
		err := pcm.createPconns()
		if err != nil {
			return
		}
	}

	select {
	case pcm.changePaths <- struct{}{}:
	default:
	}
	// Start the timer for periodic interface checking (only for client)
	duration, _ := time.ParseDuration("2s")
	if pcm.perspective == protocol.PerspectiveClient {
		pcm.timer.Reset(duration)
	} else {
		if !pcm.timer.Stop() {
			<-pcm.timer.C
		}
	}
runLoop:
	for {
		select {
		case <-pcm.closeConns:
			break runLoop
		case <-pcm.timer.C:
			err := pcm.createPconns()
			if err != nil {
				return
			}
			pcm.timer.Reset(duration)
		}
	}
	// Close pconns
	pcm.closePconns()
}

func (pcm *pconnManager) createPconn(ip net.IP) (*net.UDPAddr, error) {
	pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		return nil, err
	}
	locAddr, err := net.ResolveUDPAddr("udp", pconn.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	pcm.mutex.Lock()
	pcm.pconns[locAddr.String()] = pconn
	pcm.mutex.Unlock()
	if utils.DefaultLogger.Debug() {
		utils.DefaultLogger.Debugf("Created pconn on %s", pconn.LocalAddr().String())
	}
	// Start to listen on this new socket
	go pcm.listen(pconn)
	// Don't block
	select {
	case pcm.changePaths <- struct{}{}:
	default:
	}
	return locAddr, nil
}

func (pcm *pconnManager) createPconns() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		// TODO (QDC): do this in a generic way
		if !strings.Contains(i.Name, "eth") && !strings.Contains(i.Name, "rmnet") && !strings.Contains(i.Name, "wlan") {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			return err
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				return err
			}
			// If not Global Unicast, bypass
			if !ip.IsGlobalUnicast() {
				continue
			}
			// TODO (QDC): Clearly not optimal
			found := false
		lookingLoop:
			for _, locAddr := range pcm.localAddrs {
				if ip.Equal(locAddr.IP) {
					found = true
					break lookingLoop
				}
			}
			if !found {
				locAddr, err := pcm.createPconn(ip)
				if err != nil {
					return err
				}
				pcm.localAddrs = append(pcm.localAddrs, *locAddr)
			}
		}
	}
	return nil
}

func (pcm *pconnManager) closePconns() {
	for _, pconn := range pcm.pconns {
		err := pconn.Close()
		if err != nil {
			return
		}
	}
	err := pcm.pconnAny.Close()
	if err != nil {
		return
	}
	close(pcm.closed)
}
