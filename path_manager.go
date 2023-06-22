package quic

import (
	"errors"
	"github.com/quic-go/quic-go/logging"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/internal/utils"
)

type pathManager struct {
	pconnMgr   *pconnManager
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
	pm.connection.paths[1] = newPath

	// With the initial path, get the remoteAddr to create paths accordingly
	if conn.RemoteAddr() != nil {
		remAddr, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
		if err != nil {
			utils.DefaultLogger.Errorf("path manager: encountered error while parsing remote addr: %v", remAddr)
		}
	}

	return nil
}

func (pm *pathManager) createPath(srcAddr net.Addr, destAddr net.Addr) error {
	// First check that the path does not exist yet
	pm.connection.pathMutex.Lock()
	defer pm.connection.pathMutex.Unlock()
	paths := pm.connection.paths
	for _, pth := range paths {
		srcAddrPath := pth.srcAddress.String()
		destAddrPath := pth.destAddress.String()
		if srcAddr.String() == srcAddrPath && destAddr.String() == destAddrPath {
			// Path already exists, so don't create it again
			pm.connection.logger.Infof("path on %s and %s already exists", srcAddrPath, destAddrPath)
			return errors.New("path already exists")
		}
	}
	pathID, _ := pm.connection.config.ConnectionIDGenerator.GenerateConnectionID()

	// Build a path from the srcAddr and destAddr
	path := &path{
		pathID:   pathID,
		conn:     pm.connection,
		pathConn: newSendPconn(nil, destAddr),
	}

	pm.connection.paths[pm.connection.connIDManager.activeSequenceNumber] = path
	if pm.connection.logger.Debug() {
		pm.connection.logger.Debugf("Created path %x on %s to %s", pathID, srcAddr.String(), destAddr.String())
	}

	go path.run()
	return nil
}

// closes the path with the given connection id and deletes it from the path map in connection
func (pm *pathManager) closePath(pthID uint64) error {
	pm.connection.pathMutex.RLock()
	defer pm.connection.pathMutex.RUnlock()

	pth, ok := pm.connection.paths[pthID]
	if !ok {
		if pm.connection.logger.Debug() {
			pm.connection.logger.Debugf("no path with connection id: %i", pthID)
		}
		return errors.New("no path with connection id: " + strconv.FormatUint(pthID, 10))
	}

	err := pth.close()
	if err != nil {
		return err
	}

	delete(pm.connection.paths, pthID)
	return nil
}
