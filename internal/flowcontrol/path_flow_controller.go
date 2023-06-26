package flowcontrol

import (
	"errors"
	"fmt"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"time"
)

type pathFlowController struct {
	baseFlowController

	queueWindowUpdate func()
}

var _ PathFlowController = &pathFlowController{}

// NewPathFlowController gets a new flow controller for the path
// It is created before we receive the peer's transport parameters, thus it starts with a sendWindow of 0.

func NewPathFlowController(receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	queueWindowUpdate func(),
	allowWindowIncrease func(size protocol.ByteCount) bool,
	rttStats *utils.RTTStats,
	logger utils.Logger,
) PathFlowController {
	return &pathFlowController{
		baseFlowController: baseFlowController{
			receiveWindow:        receiveWindow,
			receiveWindowSize:    receiveWindow,
			maxReceiveWindowSize: maxReceiveWindow,
			allowWindowIncrease:  allowWindowIncrease,
			epochStartTime:       time.Time{},
			rttStats:             rttStats,
			logger:               logger,
		},
		queueWindowUpdate: queueWindowUpdate,
	}
}

func (p *pathFlowController) SendWindowSize() protocol.ByteCount {
	return p.baseFlowController.sendWindowSize()
}

func (p *pathFlowController) IncrementHighestReceived(increment protocol.ByteCount) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.highestReceived += increment
	if p.checkFlowControlViolation() {
		return &qerr.TransportError{
			ErrorCode:    qerr.FlowControlError,
			ErrorMessage: fmt.Sprintf("received %d bytes for the connection, allowed %d bytes", p.highestReceived, p.receiveWindow),
		}
	}
	return nil
}

func (p *pathFlowController) AddBytesRead(n protocol.ByteCount) {
	p.mutex.Lock()
	p.baseFlowController.addBytesRead(n)
	shouldQueueWindowUpdate := p.hasWindowUpdate()
	p.mutex.Unlock()
	if shouldQueueWindowUpdate {
		p.queueWindowUpdate()
	}
}

func (p *pathFlowController) GetWindowUpdate() protocol.ByteCount {
	p.mutex.Lock()
	oldWindowSize := p.receiveWindowSize
	offset := p.baseFlowController.getWindowUpdate()
	if oldWindowSize < p.receiveWindowSize {
		p.logger.Debugf("Increasing receive flow control window for the connection to %d kB", p.receiveWindowSize/(1<<10))
	}
	p.mutex.Unlock()
	return offset
}

// EnsureMinimumWindowSize sets a minimum window size
// it should make sure that the connection-level window is increased when a stream-level window grows
func (p *pathFlowController) EnsureMinimumWindowSize(inc protocol.ByteCount) {
	p.mutex.Lock()
	if inc > p.receiveWindowSize {
		p.logger.Debugf("Increasing receive flow control window for the connection to %d kB, in response to stream flow control window increase", p.receiveWindowSize/(1<<10))
		newSize := utils.Min(inc, p.maxReceiveWindowSize)
		if delta := newSize - p.receiveWindowSize; delta > 0 && p.allowWindowIncrease(delta) {
			p.receiveWindowSize = newSize
		}
		p.startNewAutoTuningEpoch(time.Now())
	}
	p.mutex.Unlock()
}

// Reset rests the flow controller. This happens when 0-RTT is rejected.
// All stream data is invalidated, it's if we had never opened a stream and never sent any data.
// At that point, we only have sent stream data, but we didn't have the keys to open 1-RTT keys yet.
func (p *pathFlowController) Reset() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.bytesRead > 0 || p.highestReceived > 0 || !p.epochStartTime.IsZero() {
		return errors.New("flow controller reset after reading data")
	}
	p.bytesSent = 0
	p.lastBlockedAt = 0
	return nil
}
