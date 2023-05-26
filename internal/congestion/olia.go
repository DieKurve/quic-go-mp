package congestion

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const scale uint = 10

// Olia implements the olia algorithm from MPTCP
type Olia struct {
	// Total number of bytes acked between two losses on path
	numAckBytesBetweenTwoLoses protocol.ByteCount
	// Total number of bytes acked after the last loss on path
	numAckBytesLastLoss protocol.ByteCount
	// Current number of bytes transmitted over path
	numBytesTransmitted    protocol.ByteCount
	alphaNum               int
	alphaDen               uint32
	sendCurrentWindowCount int
	// We need to keep a reference to all paths
}

func NewOlia(ackedBytes protocol.ByteCount) *Olia {
	o := &Olia{
		numAckBytesBetweenTwoLoses: ackedBytes,
		numAckBytesLastLoss:        ackedBytes,
		numBytesTransmitted:        ackedBytes,
		alphaNum:                   0,
		alphaDen:                   1,
		sendCurrentWindowCount:     0,
	}
	return o
}

func oliaScale(val uint64, scale uint) uint64 {
	return val << scale
}

// Reset sets all OLIA values to default values
func (o *Olia) Reset() {
	o.numAckBytesBetweenTwoLoses = 0
	o.numAckBytesLastLoss = 0
	o.numBytesTransmitted = 0
	o.alphaNum = 0
	o.alphaDen = 1
	o.sendCurrentWindowCount = 0
}

func (o *Olia) SmoothedBytesBetweenLosses() protocol.ByteCount {
	return utils.Max(o.numBytesTransmitted-o.numAckBytesLastLoss, o.numAckBytesLastLoss-o.numAckBytesBetweenTwoLoses)
}

func (o *Olia) UpdateAckedSinceLastLoss(ackedBytes protocol.ByteCount) {
	o.numBytesTransmitted += ackedBytes
}

func (o *Olia) OnPacketLost() {
	// TODO should we add so many if check? Not done here
	o.numAckBytesBetweenTwoLoses = o.numAckBytesLastLoss
	o.numAckBytesLastLoss = o.numBytesTransmitted
}

func (o *Olia) CongestionWindowAfterAck(currentCongestionWindow protocol.PacketNumber, rate protocol.ByteCount, congestionWindowScaled uint64) protocol.PacketNumber {
	newCongestionWindow := currentCongestionWindow
	incDen := uint64(o.alphaDen) * uint64(currentCongestionWindow) * uint64(rate)
	if incDen == 0 {
		incDen = 1
	}

	// calculate the increasing term, scaling is used to reduce the rounding effect
	if o.alphaNum == -1 {
		if uint64(o.alphaDen)*congestionWindowScaled*congestionWindowScaled < uint64(rate) {
			incNum := uint64(rate) - uint64(o.alphaDen)*congestionWindowScaled*congestionWindowScaled
			o.sendCurrentWindowCount -= int(oliaScale(incNum, scale) / incDen)
		} else {
			incNum := uint64(o.alphaDen)*congestionWindowScaled*congestionWindowScaled - uint64(rate)
			o.sendCurrentWindowCount += int(oliaScale(incNum, scale) / incDen)
		}
	} else {
		incNum := uint64(o.alphaNum)*uint64(rate) + uint64(o.alphaDen)*congestionWindowScaled*congestionWindowScaled
		o.sendCurrentWindowCount += int(oliaScale(incNum, scale) / incDen)
	}

	if o.sendCurrentWindowCount >= (1<<scale)-1 {
		newCongestionWindow++
		o.sendCurrentWindowCount = 0
	} else if o.sendCurrentWindowCount <= 0-(1<<scale)+1 {
		newCongestionWindow = utils.Max(1, currentCongestionWindow-1)
		o.sendCurrentWindowCount = 0
	}
	return newCongestionWindow
}
