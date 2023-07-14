package quic

import (
	"context"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type path struct {
	// ID of the path
	pathID protocol.ConnectionID

	// Current connection on which the path runs
	conn *connection

	// IP-Address of client
	srcAddress net.Addr
	// IP-Address of peer
	destAddress net.Addr

	// Congestion Control
	//congestionSender congestion.SendAlgorithm


	//pathPacketNumberSpace *packetNumberSpace

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

	//closeOnce sync.Once

	// closeChan is used to notify the run loop that it should terminate
	closeChan chan closeError

	sentPacket chan struct{}

	// Signals if the path gets terminated
	runClosed chan struct{}

	sendQueue sender

	framer framer

	leastUnacked protocol.PacketNumber

	lastNetworkActivityTime time.Time

	// Timer for timeouts and time stuff
	timer *utils.Timer

	handshakeCtx       context.Context
	handshakeCtxCancel context.CancelFunc

	windowUpdateQueue  *windowUpdateQueue
	datagramQueue      *datagramQueue
}

func (p *path) queueControlFrame(f wire.Frame) {
	p.framer.QueueControlFrame(f)
	p.scheduleSending()
}

func (p *path) onHasStreamData(id protocol.StreamID) {
	p.framer.AddActiveStream(id)
	p.scheduleSending()
}

func (p *path) onStreamCompleted(id protocol.StreamID) {
	if err := p.streamsMap.DeleteStream(id); err != nil {
		p.closeLocal(err)
	}
}

var (
	_ streamSender = &path{}
)

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

	p.flowController = flowcontrol.NewPathFlowController(
		protocol.ByteCount(p.conn.config.InitialConnectionReceiveWindow),
		protocol.ByteCount(p.conn.config.MaxConnectionReceiveWindow),
		p.conn.onHasConnectionWindowUpdate,
		func(size protocol.ByteCount) bool {
			if p.conn.config.AllowConnectionWindowIncrease == nil {
				return true
			}
			return p.conn.config.AllowConnectionWindowIncrease(p.conn, uint64(size))
		},
		p.rttStats,
		p.conn.logger,
	)

	// Eigene StreamsMap für jeden Path oder eine für jeden Path?
	//p.streamsMap = p.conn.streamsMap
	p.streamsMap = newStreamsMap(p, p.newFlowController, uint64(p.conn.config.MaxIncomingStreams), uint64(p.conn.config.MaxIncomingUniStreams), p.conn.perspective)
	p.streamsMap.UpdateLimits(p.conn.peerParams)

	p.framer = newFramer(p.streamsMap)

	// Initialise Timer
	p.timer = utils.NewTimer()
	p.lastNetworkActivityTime = time.Now()

	p.sendQueue = newSendQueue(p.pathConn)

	p.windowUpdateQueue = newWindowUpdateQueue(p.streamsMap, p.conn.connFlowController, p.framer.QueueControlFrame)
	p.datagramQueue = newDatagramQueue(p.scheduleSending, p.conn.logger)

	// Set path to be available
	p.status.Store(true)
}

func (p *path) close() error {
	p.sentPacketHandler.DropPackets(protocol.Encryption1RTT)
	p.status.Store(false)
	return nil
}

func (p *path) run() {
	// PATH_CHALLENGE && PATH_RESPONSE?
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
	deadline := p.lastNetworkActivityTime.Add(p.idleTimeout())

	if ackAlarm := p.receivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		deadline = ackAlarm
	}
	if lossTime := p.receivedPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		deadline = utils.MinTime(deadline, lossTime)
	}

	deadline = utils.MinTime(utils.MaxTime(deadline, time.Now().Add(10*time.Millisecond)), time.Now().Add(1*time.Second))

	p.timer.Reset(deadline)
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

/*func (p *path) onRTO(lastSentTime time.Time) bool {
	// Was there any activity since last sent packet?
	if p.lastNetworkActivityTime.Before(lastSentTime) {
		return true
	}
	return false
}*/

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
			log.Printf("Type: %s from %s", hdr.PacketType(), rp.remoteAddr.String())
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

func (p *path) LocalAddr() net.Addr {
	return p.srcAddress
}

func (p *path) RemoteAddr() net.Addr {
	return p.destAddress
}

// scheduleSending signals that we have data for sending
func (p *path) scheduleSending() {
	select {
	case p.conn.sendingScheduled <- struct{}{}:
	default:
	}
}

func (p *path) newFlowController(id protocol.StreamID) flowcontrol.StreamFlowController {
	initialSendWindow := p.conn.peerParams.InitialMaxStreamDataUni
	if id.Type() == protocol.StreamTypeBidi {
		if id.InitiatedBy() == p.conn.perspective {
			initialSendWindow = p.conn.peerParams.InitialMaxStreamDataBidiRemote
		} else {
			initialSendWindow = p.conn.peerParams.InitialMaxStreamDataBidiLocal
		}
	}
	return flowcontrol.NewStreamFlowController(
		id,
		p.conn.connFlowController,
		protocol.ByteCount(p.conn.config.InitialStreamReceiveWindow),
		protocol.ByteCount(p.conn.config.MaxStreamReceiveWindow),
		initialSendWindow,
		p.conn.onHasStreamWindowUpdate,
		p.rttStats,
		p.conn.logger,
	)
}
