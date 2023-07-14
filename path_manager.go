package quic

import (
	"errors"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"net"
	"time"
)

type pathManager struct {
	connection *connection

	runClosed          chan struct{}
	timer              *time.Timer

	logger logging.ConnectionTracer
}

func (pm *pathManager) setup() error {
	pm.runClosed = make(chan struct{}, 1)
	pm.timer = time.NewTimer(0)

	return nil
}

/*
createPath creates a new Path from the Source IP Address and the Destination IP Address
*/
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

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(srcAddr), Port: 0})
	if err != nil {
		return err
	}

	_, err = getMultiplexer().AddConn(conn, pm.connection.config.ConnectionIDGenerator.ConnectionIDLen(), pm.connection.config.StatelessResetKey, pm.connection.config.Tracer)
	if err != nil {
		return err
	}

	udpAddrDest, _ := net.ResolveUDPAddr("udp", destAddr)

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

	newPath := &path{
		pathID:         pathID,
		conn:           pm.connection,
		flowController: pathFlow,
	}

	if pm.connection.perspective == protocol.PerspectiveClient {
		newPath.pathConn = newSendPconn(conn, udpAddrDest)
	} else {
		conn, _ := wrapConn(conn)
		newPath.pathConn = newSendConn(conn, udpAddrDest, nil)
	}

	// Wird das benötigt? CID identifiziert und nicht die IP-Adressen?
	newPath.srcAddress, err = net.ResolveIPAddr("ip", srcAddr)
	if err != nil {
		return err
	}
	newPath.destAddress, err = net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	pm.connection.paths[pathID] = newPath
	if pm.connection.logger.Debug() {
		pm.connection.logger.Debugf("Created path %x on %s to %s", pathID, srcAddr, destAddr)
	}
	newPath.setup()

	go newPath.run()
	return nil
}

func (pm *pathManager) createPathServer(rp *receivedPacket) (*path, error) {
	err := pm.createPath(pm.connection.LocalAddr().String(), rp.remoteAddr.String())
	if err != nil {
		return nil, err
	}
	for _, path := range pm.connection.paths{
		if rp.remoteAddr == path.RemoteAddr(){
			return path, nil
		}
	}
	return nil ,nil
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
