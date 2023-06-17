package quic

import (
	"github.com/quic-go/quic-go/logging"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

/*const (
	minPathTimer = 10 * time.Millisecond
	// XXX (QDC): To avoid idling...
	maxPathTimer = 1 * time.Second
)*/

type path struct {
	// Connection ID of the path
	pathID protocol.ConnectionID
	// Current connection which is the path runs on
	conn *connection

	congestionSender congestion.SendAlgorithm

	pathConn sconn

	rttStats *utils.RTTStats

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedMPPacketHandler

	// Status if path is available or is on standby
	status    atomic.Bool
	closeChan chan *qerr.ApplicationError
	runClosed chan struct{}

	sentPacket chan struct{}

	lastRcvdPacketNumber protocol.PacketNumber

	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	leastUnacked protocol.PacketNumber

	lastNetworkActivityTime time.Time

	timer *utils.Timer
}

// setup initializes values that are independent of the perspective
func (p *path) setup(perspective protocol.Perspective, tracer logging.ConnectionTracer) {
	p.rttStats = &utils.RTTStats{}
	//var cong congestion.SendAlgorithm

	/*if p.conn.version >= protocol.Version1 && p.congestionSender != nil && p.pathID != p.conn.origDestConnID {
		p.congestionSender = congestion.NewCubicSender(congestion.DefaultClock{}, p.rttStats, protocol.MaxPacketBufferSize, true, tracer)
	}*/

	now := time.Now()

	p.sentPacketHandler, p.receivedPacketHandler = ackhandler.NewAckMPHandler(0, protocol.MaxPacketBufferSize, p.rttStats, true, 1, tracer, utils.DefaultLogger)

	//p.packetNumberGenerator = p.sentPacketHandler.

	p.closeChan = make(chan *qerr.ApplicationError, 1)
	p.runClosed = make(chan struct{}, 1)
	p.sentPacket = make(chan struct{}, 1)

	p.timer = utils.NewTimer()
	p.lastNetworkActivityTime = now

	p.status.Store(true)
	//p.potentiallyFailed.Store(false)

	// Once the path is set up, run it
	go p.run()
}

func (p *path) close() error {
	p.status.Store(false)
	return nil
}

func (p *path) run() {
	// XXX (QDC): relay everything to the session, maybe not the most efficient
runLoop:
	for {
		// Close immediately if requested
		select {
		case <-p.closeChan:
			break runLoop
		default:
		}

		p.maybeResetTimer()

		select {
		case <-p.closeChan:
			break runLoop
		case <-p.timer.Chan():
			p.timer.SetRead()
			select {
			case p.conn.pathTimers <- p:
			// XXX (QDC): don't remain stuck here!
			case <-p.closeChan:
				break runLoop
			case <-p.sentPacket:
				// Don't remain stuck here!
			}
		case <-p.sentPacket:
			// Used to reset the path timer
		}
	}
	err := p.close()
	if err != nil {
		return
	}
	p.sendQueue.Close()
	p.timer.Stop()
	p.runClosed <- struct{}{}
}

func (p *path) SendingAllowed() bool {
	if p.sentPacketHandler.SendMode() != ackhandler.SendNone {
		return p.status.Load()
	}
	return false
}

/*func (p *path) GetAckFrame() *wire.AckMPFrame {
	ack := p.receivedPacketHandler.GetAckMPFrame()
	if ack != nil {
		ack.DestinationConnectionIDSequenceNumber = p.pathID
	}

	return ack
}*/

/*
func (p *path) handlePathAbandonFrame() *wire.PathAbandonFrame {
	return nil
}
*/

/*
func (p *path) handlePathStatusFrame() *wire.PathStatusFrame {
	return nil
}
*/

/*
func (p *path) GetPathAbandonFrame() *wire.PathAbandonFrame {
	pathAbandonFrame := p.receivedPacketHandler.GetClosePathFrame()
	if closePathFrame != nil {
		closePathFrame.PathID = p.pathID
	}

	return closePathFrame
}*/

func (p *path) idleTimeoutStartTime() time.Time {
	return utils.MaxTime(p.lastNetworkActivityTime, p.conn.firstAckElicitingPacketAfterIdleSentTime)
}

func (p *path) maybeResetTimer() {
	//deadline := p.lastNetworkActivityTime.Add(p.idleTimeout())

	if ackAlarm := p.receivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		deadline = ackAlarm
	}
	if lossTime := p.receivedPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		deadline = utils.MinTime(deadline, lossTime)
	}

	deadline = utils.MinTime(utils.MaxTime(deadline, time.Now().Add(10*time.Millisecond)), time.Now().Add(1*time.Second))

	p.timer.Reset(deadline)
}

/*
func (p *path) idleTimeout() time.Duration {
	// TODO (QDC): probably this should be refined at path level
	cryptoSetup := p.conn.cr
	if cryptoSetup != nil {
		if p.open.Load() && (p.pathID != 0 || p.conn.handshakeComplete) {
			return p.conn.connectionParameters.GetIdleConnectionStateLifetime()
		}
		return p.conn.config.HandshakeTimeout
	}
	return time.Second
}*/

func (p *path) handlePacketImpl(pkt *receivedPacket) error {
	if !p.status.Load() {
		// Path is closed, ignore packet
		return nil
	}

	if !pkt.rcvTime.IsZero() {
		p.lastNetworkActivityTime = pkt.rcvTime
	}
	data := pkt.data
	hdr, _, _, _ := wire.ParsePacket(data)

	// We just received a new packet on that path, so it works
	//p.potentiallyFailed.Store(false)
	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		p.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	packet, err := p.conn.unpacker.UnpackLongHeader(hdr.Raw, hdr, data)
	if utils.DefaultLogger.Debug() {
		if err != nil {
			utils.DefaultLogger.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.pathID)
		} else {
			utils.DefaultLogger.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x, %s", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.pathID, packet.encryptionLevel)
		}
	}

	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.TransportErrorCode); ok && quicErr.String() == qerr.InternalError.String() {
		return err
	}
	if p.conn.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		p.conn.RemoteAddr()
	}
	if err != nil {
		return err
	}

	p.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrupting, so we are sure the packet is not attacker-controlled
	p.largestRcvdPacketNumber = utils.Max(p.largestRcvdPacketNumber, hdr.PacketNumber)

	isRetransmittable := ackhandler.HasAckElicitingFrames(packet.data[0])
	if err = p.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, isRetransmittable); err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return p.conn.handleFrames(packe, p)
}

func (p *path) onRTO(lastSentTime time.Time) bool {
	// Was there any activity since last sent packet?
	if p.lastNetworkActivityTime.Before(lastSentTime) {
		//p.potentiallyFailed.Store(true)
		p.conn.schedulePathsFrame()
		return true
	}
	return false
}

func (p *path) SetLeastUnacked(leastUnacked protocol.PacketNumber) {
	p.leastUnacked = leastUnacked
}
