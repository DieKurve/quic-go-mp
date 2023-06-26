package quic

import (
	"errors"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/utils"
)

type pathManager struct {
	connection *connection

	handshakeCompleted chan struct{}
	runClosed          chan struct{}
	timer              *time.Timer

	logger logging.ConnectionTracer
}

func (pm *pathManager) setup(conn *connection) error {

	pm.handshakeCompleted = make(chan struct{}, 1)
	pm.runClosed = make(chan struct{}, 1)
	pm.timer = time.NewTimer(0)

	pm.connection.conn.LocalAddr()

	pathConn := &sconn{
		rawConn:    nil,
		remoteAddr: conn.conn.RemoteAddr(),
		info:       nil,
		oob:        nil,
	}
	// Set up the first path of the connection with the underlying connection
	newPath := &path{
		pathID:   pm.connection.handshakeDestConnID,
		conn:     pm.connection,
		pathConn: pathConn,
	}
	pm.connection.paths[pm.connection.handshakeDestConnID] = newPath

	// With the initial path, get the remoteAddr to create paths accordingly
	if conn.RemoteAddr() != nil {
		remAddr, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
		if err != nil {
			utils.DefaultLogger.Errorf("path manager: encountered error while parsing remote addr: %v", remAddr)
		}
	}

	return nil
}

func (pm *pathManager) createPath(srcAddr string, destAddr string) error {
	// First check that the path does not exist yet
	pm.connection.pathLock.Lock()
	defer pm.connection.pathLock.Unlock()
	paths := pm.connection.paths
	// check if path exits already
	for _, pth := range paths {
		srcAddrPath := pth.srcAddress.String()
		destAddrPath := pth.destAddress.String()
		if srcAddr == srcAddrPath && destAddr == destAddrPath {
			pm.connection.logger.Infof("path on %s and %s already exists", srcAddrPath, destAddrPath)
			return errors.New("path already exists")
		}
	}
	pathID, _ := pm.connection.config.ConnectionIDGenerator.GenerateConnectionID()

	udpAddrSrc, _ := net.ResolveUDPAddr("udp", srcAddr)
	udpAddrDest, _ := net.ResolveUDPAddr("udp", destAddr)
	conn, _ := net.ListenUDP("udp", udpAddrSrc)

	pathFlow := flowcontrol.NewPathFlowController(
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
	)

	path := &path{
		pathID:         pathID,
		conn:           pm.connection,
		flowController: pathFlow,
	}

	if pm.connection.perspective == protocol.PerspectiveClient {
		path.pathConn = newSendPconn(conn, udpAddrDest)
	} else {
		conn, _ := wrapConn(conn)
		path.pathConn = newSendConn(conn, udpAddrDest, nil)
	}

	pm.connection.paths[pathID] = path
	if pm.connection.logger.Debug() {
		pm.connection.logger.Debugf("Created path %x on %s to %s", pathID, srcAddr, destAddr)
	}
	path.setup()

	go path.run()
	return nil
}

// closes the path with the given connection id and deletes it from the path map in connection
func (pm *pathManager) closePath(pthID protocol.ConnectionID) error {
	pm.connection.pathLock.RLock()
	defer pm.connection.pathLock.RUnlock()

	pth, ok := pm.connection.paths[pthID]
	if !ok {
		if pm.connection.logger.Debug() {
			pm.connection.logger.Debugf("no path with connection id: %i", pthID)
		}
		return errors.New("no path with connection id: " + pthID.String())
	}

	err := pth.close()
	if err != nil {
		return err
	}

	// Delete path if all packets are either acknowledged or dropped
	delete(pm.connection.paths, pthID)
	return nil
}
