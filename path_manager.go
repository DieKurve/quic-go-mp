package quic

import (
	"errors"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type pathManager struct {
	pconnMgr  *pconnManager
	conn      *connection
	nxtPathID protocol.ConnectionID
	// Number of paths, excluding the initial one
	nbPaths uint8

	remoteAddrs4 []net.UDPAddr
	remoteAddrs6 []net.UDPAddr

	advertisedLocAddrs map[string]bool

	// TODO (QDC): find a cleaner way
	cubics map[protocol.ConnectionID]*congestion.Cubic

	handshakeCompleted chan struct{}
	runClosed          chan struct{}
	timer              *time.Timer

	logger logging.ConnectionTracer
}

func (pm *pathManager) setup(conn *connection) {

	connIDPath, err := protocol.GenerateConnectionIDForInitial()
	pm.nxtPathID = connIDPath
	if err != nil {
		return
	}

	pm.remoteAddrs4 = make([]net.UDPAddr, 0)
	pm.remoteAddrs6 = make([]net.UDPAddr, 0)
	pm.advertisedLocAddrs = make(map[string]bool)
	pm.handshakeCompleted = make(chan struct{}, 1)
	pm.runClosed = make(chan struct{}, 1)
	pm.timer = time.NewTimer(0)
	pm.nbPaths = 0

	pm.cubics = map[protocol.ConnectionID]*congestion.Cubic{}

	// Set up the first path of the connection
	pm.conn.paths[1] = &path{
		pathID:   pm.nxtPathID,
		conn:     pm.conn,
		pathConn: sconn{},
	}

	// Setup this first path
	pm.conn.paths[1].setup()

	// With the initial path, get the remoteAddr to create paths accordingly
	if conn.RemoteAddr() != nil {
		remAddr, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
		if err != nil {
			utils.DefaultLogger.Errorf("path manager: encountered error while parsing remote addr: %v", remAddr)
		}

		if remAddr.IP.To4() != nil {
			pm.remoteAddrs4 = append(pm.remoteAddrs4, *remAddr)
		} else {
			pm.remoteAddrs6 = append(pm.remoteAddrs6, *remAddr)
		}
	}

	// Launch the path manager
	go pm.run()
}

func (pm *pathManager) run() {
	// Close immediately if requested
	select {
	case <-pm.runClosed:
		return
	case <-pm.handshakeCompleted:
		if pm.conn.multipathEnabled {
			err := pm.createPaths()
			if err != nil {
				pm.closePaths()
				return
			}
		}
	}

runLoop:
	for {
		select {
		case <-pm.runClosed:
			break runLoop
		case <-pm.pconnMgr.changePaths:
			if pm.conn.multipathEnabled {
				err := pm.createPaths()
				if err != nil {
					return
				}
			}
		}
	}
	// Close paths
	pm.closePaths()
}

func getIPVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func (pm *pathManager) advertiseAddresses() {
	pm.pconnMgr.mutex.Lock()
	defer pm.pconnMgr.mutex.Unlock()
	for _, locAddr := range pm.pconnMgr.localAddrs {
		_, sent := pm.advertisedLocAddrs[locAddr.String()]
		if !sent {
			//version := getIPVersion(locAddr.IP)
			//pm.conn.framer.AddAddressForTransmission(uint8(version), locAddr)
			pm.advertisedLocAddrs[locAddr.String()] = true
		}
	}
}

func (pm *pathManager) createPath(locAddr net.UDPAddr, remAddr net.UDPAddr) error {
	// First check that the path does not exist yet
	pm.conn.pathMutex.Lock()
	defer pm.conn.pathMutex.Unlock()
	paths := pm.conn.paths
	for _, pth := range paths {
		locAddrPath := pth.conn.LocalAddr().String()
		remAddrPath := pth.conn.RemoteAddr().String()
		if locAddr.String() == locAddrPath && remAddr.String() == remAddrPath {
			// Path already exists, so don't create it again
			return nil
		}
	}
	// No matching path, so create it
	/*pth := &path{
		pathID: pm.nxtPathID,
		conn:   pm.conn,
		pathConn:  sconn{remoteAddr: &remAddr},
	}*/
	//pth.setup(pm.cubics)
	//pm.conn.paths[pm.nxtPathID] = pth
	if utils.DefaultLogger.Debug() {
		utils.DefaultLogger.Debugf("Created path %x on %s to %s", pm.nxtPathID, locAddr.String(), remAddr.String())
	}
	nxtPathID, err := protocol.GenerateConnectionID(10)
	pm.nxtPathID = nxtPathID
	if err != nil {
		return err
	}
	// Send a PING frame to get latency info about the new path and informing the
	// peer of its existence
	// Because we hold pathsLock, it is safe to send packet now
	return nil
}

func (pm *pathManager) createPaths() error {
	if utils.DefaultLogger.Debug() {
		utils.DefaultLogger.Debugf("Path manager tries to create paths")
	}

	// XXX (QDC): don't let the server create paths for now
	if pm.conn.perspective == protocol.PerspectiveServer {
		pm.advertiseAddresses()
		return nil
	}
	// TODO (QDC): clearly not optimal
	pm.pconnMgr.mutex.Lock()
	defer pm.pconnMgr.mutex.Unlock()
	for _, locAddr := range pm.pconnMgr.localAddrs {
		version := getIPVersion(locAddr.IP)
		if version == 4 {
			for _, remAddr := range pm.remoteAddrs4 {
				err := pm.createPath(locAddr, remAddr)
				if err != nil {
					return err
				}
			}
		} else {
			for _, remAddr := range pm.remoteAddrs6 {
				err := pm.createPath(locAddr, remAddr)
				if err != nil {
					return err
				}
			}
		}
	}
	pm.conn.schedulePathsFrame()
	return nil
}

func (pm *pathManager) createPathFromRemote(hdr *wire.Header, p *receivedPacket) (*path, error) {
	pm.conn.pathMutex.Lock()
	defer pm.conn.pathMutex.Unlock()
	localPconn := p.info
	remoteAddr := p.remoteAddr
	pathCID := hdr.DestConnectionID

	// Sanity check: pathCID should not exist yet
	_, ko := pm.conn.paths[1]
	if ko {
		return nil, errors.New("trying to create already existing path")
	}

	pth := &path{
		pathID:   pathCID,
		conn:     pm.conn,
		pathConn: sconn{remoteAddr: remoteAddr},
	}

	pth.setup()
	pm.conn.paths[1] = pth

	if utils.DefaultLogger.Debug() {
		utils.DefaultLogger.Debugf("Created remote path %x on %s to %s", pathCID, localPconn.addr.String(), remoteAddr.String())
	}

	return pth, nil
}

func (pm *pathManager) closePath(pthID protocol.ConnectionID) error {
	pm.conn.pathMutex.RLock()
	defer pm.conn.pathMutex.RUnlock()

	pth, ok := pm.conn.paths[1]
	if !ok {
		// XXX (QDC) Unknown path, what should we do?
		return nil
	}

	if pth.status.Load() {
		//pth.closeChan <- nil
	}

	return nil
}

func (pm *pathManager) closePaths() {
	pm.conn.pathMutex.RLock()
	paths := pm.conn.paths
	for _, pth := range paths {
		if pth.status.Load() {
			select {
			//case pth.closeChan <- nil:
			default:
				// Don't remain stuck here!
			}
		}
	}
	pm.conn.pathMutex.RUnlock()
}
