package quic

import (
	"context"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	"log"
	"math"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	validating = iota
		active
		closing
		closed
)

// Path is network path for redundancy and resiliance
// It is build on top an already existing QUIC connection
// The Path uses a new UDP connection and closes it if path is closed
type path struct {
	// ID of the path
	pathID protocol.ConnectionID

	// Current connection on which the path runs
	conn *connection

	// Congestion Control
	//congestionSender congestion.SendAlgorithm

	streamsMap streamManager

	// sendConn for the current path
	pathConn sendConn

	rttStats *utils.RTTStats

	framer framer

	sendQueuePath sender

	// Flowcontroller for the packets send on this path
	flowPathController flowcontrol.PathFlowController

	// Handler for receiving and sending Packets on this path
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedMPPacketHandler

	// Status if path is available or is on standby
	// True if path is available
	// False if path is in standby
	status atomic.Bool

	closeOnce sync.Once

	// closeChan is used to notify the run loop that it should terminate
	closeChan chan closeError

	sentPacket chan struct{}

	// Signals if the path gets terminated
	runClosed chan struct{}

	leastUnacked protocol.PacketNumber

	// Timer for timeouts and time stuff
	timer connectionTimer

	handshakeCtx       context.Context
	handshakeCtxCancel context.CancelFunc
	ctxCancel          context.CancelFunc
	// The idle timeout is set based on the max of the time we received the last packet...
	lastPacketReceivedTime time.Time
	// ... and the time we sent a new ack-eliciting packet after receiving a packet.
	firstAckElicitingPacketAfterIdleSentTime time.Time
	creationTime                             time.Time

	// Current path challenge for PATH_CHALLENGE and PATH_RESPONSE
	pathChallenge [8]byte

	// pathStatus: Path Status as specified in Multipath Extension for QUIC Draft 5
	// Validating, Active, Closing, Closed
	pathStatus uint8

	// Channel which waits that path is validated by the peer
	pathValidation   chan struct{}

	// Channel if packet sending was scheduled
	sendingScheduled chan struct{}
}



// setup initializes values that are independent of the perspective
func (p *path) setup() {
	p.pathStatus = validating
	p.rttStats = &utils.RTTStats{}

	p.sendQueuePath = newSendQueue(p.pathConn)

	p.flowPathController = flowcontrol.NewPathFlowController(
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

	p.streamsMap = newStreamsMap(
		p,
		p.newFlowController,
		uint64(p.conn.config.MaxIncomingStreams),
		uint64(p.conn.config.MaxIncomingUniStreams),
		p.conn.perspective,
	)

	p.framer = newFramer(p.streamsMap)

	now := time.Now()
	p.lastPacketReceivedTime = now
	p.creationTime = now

	// Create Channels
	p.closeChan = make(chan closeError, 1)
	p.runClosed = make(chan struct{}, 1)
	p.sentPacket = make(chan struct{}, 1)
	p.pathValidation = make(chan struct{}, 1)
	p.sendingScheduled = make(chan struct{}, 1)

	// Initialize Timer
	p.lastPacketReceivedTime = time.Now()

	// Create sentPackethandler and receivedPacketHandler for sending and receiving Packets
	p.sentPacketHandler, p.receivedPacketHandler = ackhandler.NewAckMPHandler(
		1,
		getMaxPacketSize(p.pathConn.RemoteAddr()),
		p.rttStats,
		true,
		p.conn.getPerspective(),
		p.conn.tracer,
		p.conn.logger,
		true,
	)

	// Validate the path (PATH_CHALLENGE -> Server | Server -> PATH_RESPONSE)
	p.validatePeer()

	select {
	case <- p.pathValidation:
	case <-time.After(10*time.Second):
		log.Printf("Timeout path validation")
	}

	// Set path to be available
	p.status.Store(true)
	p.pathStatus = active

	go p.run()
}

func (p *path) close() error {
	<-p.runClosed
	p.status.Store(false)
	p.pathStatus = closed
	return nil
}

func (p *path) run() {

	defer p.ctxCancel()

	p.timer = *newTimer()

	// Initial and Handshake

runLoop:
	for {
		// Close immediately if requested
		select {
		case <-p.closeChan:
			break runLoop
		default:
		}

		select {
		case <-p.closeChan:
			break runLoop
		case <-p.timer.Chan():
			p.timer.SetRead()
			select {
			case p.conn.pathTimers <- p:
			case <-p.closeChan:
				break runLoop
			case <-p.sentPacket:

			}
		case <-p.sentPacket:
			// Used to reset the path timer
		}
	}
	err := p.close()
	if err != nil {
		return
	}
	p.sendQueuePath.Close()
	p.timer.Stop()
	p.runClosed <- struct{}{}
	return

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
		p.flowPathController,
		protocol.ByteCount(p.conn.config.InitialStreamReceiveWindow),
		protocol.ByteCount(p.conn.config.MaxStreamReceiveWindow),
		initialSendWindow,
		p.conn.onHasStreamWindowUpdate,
		p.rttStats,
		p.conn.logger,
	)
}

func (p *path) SendingAllowed() bool {
	if p.sentPacketHandler.SendMode() != ackhandler.SendNone {
		return p.status.Load()
	}
	return false
}

func (p *path) idleTimeoutStartTime() time.Time {
	return utils.MaxTime(p.lastPacketReceivedTime, p.conn.firstAckElicitingPacketAfterIdleSentTime)
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
		p.lastPacketReceivedTime = rp.rcvTime
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
	return p.pathConn.LocalAddr()
}

func (p *path) RemoteAddr() net.Addr {
	return p.pathConn.RemoteAddr()
}

func (p *path) sendPathAbandon(e error) ([]byte, error) {
	var packetMP *coalescedPacketMP
	var packet *coalescedPacket
	var err error
	var transportErr *qerr.TransportError
	var applicationErr *qerr.ApplicationError
	if errors.As(e, &applicationErr) {
		packetMP, err = p.conn.packerMP.PackPathAbandon(applicationErr, 0, p.conn.version)
	} else if errors.As(e, &transportErr) {
		packet, err = p.conn.packer.PackConnectionClose(transportErr, p.conn.version)
	} else {
		packet, err = p.conn.packer.PackConnectionClose(&qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: fmt.Sprintf("connection BUG: unspecified error type (msg: %s)", e.Error()),
		}, p.conn.version)
	}
	if err != nil {
		return nil, err
	}
	if packet != nil {
		p.conn.logCoalescedPacket(packet)
		p.pathStatus = closing
		return packet.buffer.Data, p.pathConn.Write(packet.buffer.Data)
	} else if packetMP != nil {
		p.conn.logCoalescedPacketMP(packetMP)
		return packetMP.buffer.Data, p.pathConn.Write(packet.buffer.Data)
	}

	return nil, nil
}

func (p* path) validatePeer() {
	p.pathChallenge = [8]byte{
		uint8(rand.Intn(math.MaxUint8 + 1)),
		uint8(rand.Intn(math.MaxUint8 + 1)),
		uint8(rand.Intn(math.MaxUint8 + 1)),
		uint8(rand.Intn(math.MaxUint8 + 1)),
		uint8(rand.Intn(math.MaxUint8 + 1)),
		uint8(rand.Intn(math.MaxUint8 + 1)),
		uint8(rand.Intn(math.MaxUint8 + 1)),
		uint8(rand.Intn(math.MaxUint8 + 1)),
	}
	w := &wire.PathChallengeFrame{Data: p.pathChallenge}
	p.queueControlFrame(w)
	return
}

// AcceptStream returns the next stream opened by the peer
func (p *path) AcceptStream(ctx context.Context) (Stream, error) {
	return p.conn.streamsMap.AcceptStream(ctx)
}

func (p *path) AcceptUniStream(ctx context.Context) (ReceiveStream, error) {
	return p.conn.streamsMap.AcceptUniStream(ctx)
}

// OpenStream opens a stream
func (p *path) OpenStream() (Stream, error) {
	return p.conn.streamsMap.OpenStream()
}

func (p *path) OpenStreamSync(ctx context.Context) (Stream, error) {
	return p.conn.streamsMap.OpenStreamSync(ctx)
}

func (p *path) OpenUniStream() (SendStream, error) {
	return p.conn.streamsMap.OpenUniStream()
}

func (p *path) OpenUniStreamSync(ctx context.Context) (SendStream, error) {
	return p.conn.streamsMap.OpenUniStreamSync(ctx)
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

func (p *path) scheduleSending() {
	select {
	case p.sendingScheduled <- struct{}{}:
	default:
	}
}