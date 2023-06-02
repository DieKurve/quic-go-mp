package wire

import "sync"

var ackMPFramePool = sync.Pool{New: func() any {
	return &AckMPFrame{}
}}

func GetAckMPFrame() *AckMPFrame {
	f := ackMPFramePool.Get().(*AckMPFrame)
	//f.DestinationConnectionIDSequenceNumber = 0
	f.AckRanges = f.AckRanges[:0]
	f.DelayTime = 0
	f.ECNCE = 0
	f.ECT0 = 0
	f.ECT1 = 0
	return f
}

func PutAckMPFrame(f *AckMPFrame) {
	if cap(f.AckRanges) > 4 {
		return
	}
	ackMPFramePool.Put(f)
}
