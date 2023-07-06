package quic

import (
	"context"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type path struct {
	// Connection ID of the path
	pathID protocol.ConnectionID

	// Current connection which is the path runs on
	conn *connection

	// IP-Address of client
	srcAddress net.Addr
	// IP-Address of peer
	destAddress net.Addr

	// Congestion Control
	//congestionSender congestion.SendAlgorithm

	streamsMap streamManager

	pathConn sendConn

	rttStats *utils.RTTStats

	// Flowcontroller for the packets send on this path
	flowController flowcontrol.PathFlowController

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedMPPacketHandler

	// Status if path is available or is on standby
	// True if path is available
	// False if path is in standby
	status    atomic.Bool
	runClosed chan struct{}
	closeOnce sync.Once
	// closeChan is used to notify the run loop that it should terminate
	closeChan chan closeError

	sendQueue sender

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
func (p *path) setup() {
	p.rttStats = &utils.RTTStats{}

	// Create sentPackethandler and receivedPacketHandler for sending and receiving Packets
	p.sentPacketHandler, p.receivedPacketHandler = ackhandler.NewAckMPHandler(
		0,
		protocol.MaxPacketBufferSize,
		p.rttStats,
		true,
		p.conn.getPerspective(),
		nil,
		p.conn.logger,
	)
	// Create Channels
	p.closeChan = make(chan closeError, 1)
	p.runClosed = make(chan struct{}, 1)
	p.sentPacket = make(chan struct{}, 1)

	// Initialise Timer
	p.timer = utils.NewTimer()
	p.lastNetworkActivityTime = time.Now()

	p.sendQueue = newSendQueue(p.pathConn)

	// Set path to be available
	p.status.Store(true)

	p.streamsMap = p.conn.streamsMap
}

func (p *path) close() error {
	p.sentPacketHandler.DropPackets(protocol.Encryption1RTT)
	p.status.Store(false)
	return nil
}

func (p *path) run() {
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

func (p *path) idleTimeoutStartTime() time.Time {
	return utils.MaxTime(p.lastNetworkActivityTime, p.conn.firstAckElicitingPacketAfterIdleSentTime)
}

func (p *path) maybeResetTimer() {
	//deadline := p.lastNetworkActivityTime.Add(p.idleTimeout())

	if ackAlarm := p.receivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		//deadline = ackAlarm
	}
	if lossTime := p.receivedPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		//deadline = utils.MinTime(deadline, lossTime)
	}

	//deadline = utils.MinTime(utils.MaxTime(deadline, time.Now().Add(10*time.Millisecond)), time.Now().Add(1*time.Second))

	//p.timer.Reset(deadline)
}

func (p *path) idleTimeout() time.Duration {
	// TODO (QDC): probably this should be refined at path level
	cryptoSetup := p.conn.cryptoStreamManager
	if cryptoSetup != nil {
		if p.status.Load() && p.conn.handshakeComplete {
			return p.conn.config.MaxIdleTimeout
		}
		return p.conn.config.handshakeTimeout()
	}
	return time.Second
}

func (p *path) closeLocal(e error) {
	p.conn.closeOnce.Do(func() {
		if e == nil {
			p.conn.logger.Infof("Closing path.")
		} else {
			p.conn.logger.Errorf("Closing path with error: %s", e)
		}
		p.closeChan <- closeError{err: e, immediate: false, remote: false}
	})
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

// AcceptStream returns the next stream opened by the peer
func (p *path) AcceptStream(ctx context.Context) (Stream, error) {
	return p.streamsMap.AcceptStream(ctx)
}

func (p *path) AcceptUniStream(ctx context.Context) (ReceiveStream, error) {
	return p.streamsMap.AcceptUniStream(ctx)
}

// OpenStream opens a stream
func (p *path) OpenStream() (Stream, error) {
	return p.streamsMap.OpenStream()
}

func (p *path) OpenStreamSync(ctx context.Context) (Stream, error) {
	return p.streamsMap.OpenStreamSync(ctx)
}

func (p *path) OpenUniStream() (SendStream, error) {
	return p.streamsMap.OpenUniStream()
}

func (p *path) OpenUniStreamSync(ctx context.Context) (SendStream, error) {
	return p.streamsMap.OpenUniStreamSync(ctx)
}

func (p *path) handlePacketImpl(rp *receivedPacket) bool {
	if !p.status.Load() {
		// Path is closed, ignore packet
		return false
	}
	if wire.IsVersionNegotiationPacket(rp.data) {
		p.conn.handleVersionNegotiationPacket(rp)
		return false
	}

	if !rp.rcvTime.IsZero() {
		p.lastNetworkActivityTime = rp.rcvTime
	}

	var counter uint8
	var lastConnID protocol.ConnectionID
	var processed bool
	data := rp.data
	pkt := rp
	for len(data) > 0 {
		var destConnID protocol.ConnectionID
		if counter > 0 {
			pkt = pkt.Clone()
			pkt.data = data

			var err error
			destConnID, err = wire.ParseConnectionID(pkt.data, p.pathID.Len())
			if err != nil {
				if p.conn.tracer != nil {
					p.conn.tracer.DroppedPacket(logging.PacketTypeNotDetermined, protocol.ByteCount(len(data)), logging.PacketDropHeaderParseError)
				}
				p.conn.logger.Debugf("error parsing packet, couldn't parse connection ID: %s", err)
				break
			}
			if destConnID != lastConnID {
				if p.conn.tracer != nil {
					p.conn.tracer.DroppedPacket(logging.PacketTypeNotDetermined, protocol.ByteCount(len(data)), logging.PacketDropUnknownConnectionID)
				}
				p.conn.logger.Debugf("coalesced packet has different destination connection ID: %s, expected %s", destConnID, lastConnID)
				break
			}
		}

		if wire.IsLongHeaderPacket(pkt.data[0]) {
			hdr, packetData, rest, err := wire.ParsePacket(pkt.data)
			if err != nil {
				if p.conn.tracer != nil {
					dropReason := logging.PacketDropHeaderParseError
					if err == wire.ErrUnsupportedVersion {
						dropReason = logging.PacketDropUnsupportedVersion
					}
					p.conn.tracer.DroppedPacket(logging.PacketTypeNotDetermined, protocol.ByteCount(len(data)), dropReason)
				}
				p.conn.logger.Debugf("error parsing packet: %s", err)
				break
			}
			lastConnID = hdr.DestConnectionID

			if hdr.Version != p.conn.version {
				if p.conn.tracer != nil {
					p.conn.tracer.DroppedPacket(logging.PacketTypeFromHeader(hdr), protocol.ByteCount(len(data)), logging.PacketDropUnexpectedVersion)
				}
				p.conn.logger.Debugf("Dropping packet with version %x. Expected %x.", hdr.Version, p.conn.version)
				break
			}

			if counter > 0 {
				pkt.buffer.Split()
			}
			counter++

			// only log if this actually a coalesced packet
			if p.conn.logger.Debug() && (counter > 1 || len(rest) > 0) {
				p.conn.logger.Debugf("Parsed a coalesced packet. Part %d: %d bytes. Remaining: %d bytes.", counter, len(packetData), len(rest))
			}

			pkt.data = packetData

			if wasProcessed := p.conn.handleLongHeaderPacket(pkt, hdr); wasProcessed {
				processed = true
			}
			data = rest
		} else {
			if counter > 0 {
				pkt.buffer.Split()
			}
			processed = p.conn.handleShortHeaderPacket(pkt, destConnID)
			break
		}
	}

	pkt.buffer.MaybeRelease()
	return processed
}

func (p *path) GetPathID() string {
	return p.pathID.String()
}
