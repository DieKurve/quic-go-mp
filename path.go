package quic

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type path struct {
	// Connection ID of the path
	pathID protocol.ConnectionID
	// Sequence Number of the path
	pathSeqNum uint64

	// Current connection which is the path runs on
	conn *connection

	srcAddress net.Addr
	destAddress net.Addr

	congestionSender congestion.SendAlgorithm

	pathConn sendConn

	rttStats *utils.RTTStats

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

}

func (p *path) close() error {
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
	//p.sendQueue.Close()
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
}

func (p *path) handlePacketImpl(rp *receivedPacket) bool {
	return p.conn.handlePacketImpl(rp)
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
