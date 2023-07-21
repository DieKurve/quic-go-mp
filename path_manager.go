package quic

import (
	"crypto/tls"
	"errors"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"log"
	"net"
	"time"
)

type pathManager struct {
	connection *connection

	paths uint8

	runClosed chan struct{}
	timer     *time.Timer

	logger logging.ConnectionTracer

	destinationAddrs []*net.UDPAddr

	// Handshaking
	handshakeCompleteChan chan struct{}
	handshakeComplete     bool
	handshakeConfirmed    bool
}

func (pm *pathManager) setup() error {
	pm.runClosed = make(chan struct{}, 1)
	pm.timer = time.NewTimer(0)

	pm.handshakeCompleteChan = make(chan struct{}, 1)

	pm.paths = 0

	go pm.run()

	return nil
}

/*
createPath creates a new Path from the Source IP Address and the Destination IP Address
*/
func (pm *pathManager) createPath(srcAddr string, destAddr string, tlsconfig *tls.Config) error {
	// First check that the path does not exist yet
	pm.connection.pathLock.Lock()
	defer pm.connection.pathLock.Unlock()
	paths := pm.connection.paths
	// check if path exists already
	for _, pth := range paths {
		srcAddrPath := pth.pathConn.LocalAddr().String()
		destAddrPath := pth.pathConn.RemoteAddr().String()
		if srcAddr == srcAddrPath && destAddr == destAddrPath {
			pm.connection.logger.Infof("path on %s and %s already exists", srcAddrPath, destAddrPath)
			return errors.New("path already exists")
		}
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(srcAddr), Port: 0})
	if err != nil {
		return err
	}

	pathPacketHandler, err := getMultiplexer().AddConn(conn, pm.connection.config.ConnectionIDGenerator.ConnectionIDLen(), pm.connection.config.StatelessResetKey, pm.connection.config.Tracer)
	if err != nil {
		return err
	}

	udpAddrDest, err := net.ResolveUDPAddr("udp", pm.connection.conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	pm.destinationAddrs = append(pm.destinationAddrs, udpAddrDest)

	/*pathFlow := flowcontrol.NewPathFlowController(
		protocol.ByteCount(pm.connection.config.InitialConnectionReceiveWindow),
		protocol.ByteCount(pm.connection.config.MaxConnectionReceiveWindow),
		pm.connection.onHasConnectionWindowUpdate,
		func(size protocol.ByteCount) bool {
			if pm.connection.config.AllowConnectionWindowIncrease == nil {
				return true
			}
			return pm.connection.config.AllowConnectionWindowIncrease(pm.connection, uint64(size))
		},
		pm.connection.rttStats,
		pm.connection.logger,
	)*/

	pathID, _ := pm.connection.config.ConnectionIDGenerator.GenerateConnectionID()

	newPath := &path{
		pathID: pathID,
		conn:   pm.connection,
	}

	pathPacketHandler.Add(pathID, newPath.conn)

	if pm.connection.perspective == protocol.PerspectiveClient {
		newPath.pathConn = newSendPconn(conn, udpAddrDest)
	} else {
		pconn, _ := wrapConn(conn)
		newPath.pathConn = newSendConn(pconn, udpAddrDest, nil)
	}

	pm.connection.paths[pathID] = newPath


	newPath.setup()

	log.Printf("Created path %x on %s to %s", pathID, srcAddr, destAddr)
	if pm.connection.logger.Debug() {
		pm.connection.logger.Debugf("Created path %x on %s to %s", pathID, srcAddr, destAddr)
	}

	return nil
}

func (pm *pathManager) createPathServer(rp *receivedPacket) (*path, error) {
	// check if path is already exists
	for _, path := range pm.connection.paths {
		if rp.remoteAddr == path.RemoteAddr() {
			return path, nil
		}
	}
	// create path from receivedPacket remote address
	err := pm.createPath(pm.connection.LocalAddr().String(), rp.remoteAddr.String(), pm.connection.tlsconfig)
	if err != nil {
		return nil, err
	}
	pm.paths++
	return nil, nil
}

// closes the path with the given connection id and deletes it from the path map in connection
func (pm *pathManager) closePath(pathID protocol.ConnectionID) error {
	pm.connection.pathLock.RLock()
	defer pm.connection.pathLock.RUnlock()

	pth, ok := pm.connection.paths[pathID]
	if !ok {
		if pm.connection.logger.Debug() {
			pm.connection.logger.Debugf("no path with connection id: %i", pathID)
		}
		return errors.New("no path with connection id: " + pathID.String())
	}

	err := pth.close()
	if err != nil {
		return err
	}

	// Delete path if all packets are either acknowledged or dropped
	delete(pm.connection.paths, pathID)
	pm.paths--
	pm.connection.connIDGenerator.retireConnectionID(pathID)
	return nil
}

func (pm *pathManager) closeAllPaths() error {
	pm.connection.pathLock.RLock()
	defer pm.connection.pathLock.RUnlock()
	for pathID := range pm.connection.paths {
		err := pm.connection.paths[pathID].close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (pm *pathManager) createPathFromRemote(p *receivedPacket) error {
	pm.connection.pathLock.Lock()
	defer pm.connection.pathLock.Unlock()
	err := pm.createPath(p.remoteAddr.String(), "", nil)
	if err != nil{
		return err
	}
	return nil
}

func (pm *pathManager) run() {
runLoop:
	for {
		select {
		case <-pm.runClosed:
			break runLoop
		}
	}
	// Close all paths
	err := pm.closeAllPaths()
	if err != nil {
		return
	}
}
