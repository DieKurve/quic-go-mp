package wire

import "time"

/*
The ACK_MP frame (types TBD-00 and TBD-01; experiments use 0xbaba00..0xbaba01)
is an extension of the ACK frame defined by RFC9000. It is used to acknowledge
packets that were sent on different paths using multiple packet number spaces.
If the frame type is TBD-01, ACK_MP frames also contain the sum of QUIC packets
with associated ECN marks received on the connection up to this point
*/

// A AckMPFrame as described by draft-ietf-quic-multipath (version 4)
type AckMPFrame struct {
	DestinationConnectionIDSequenceNumber uint64        // The sequence number of the Connection ID identifying the packet number space of the 1-RTT packets which are acknowledged by the ACK_MP frame.
	DelayTime                             time.Duration // A variable-length integer encoding the acknowledgment delay in microseconds. It is decoded by multiplying the value in the field by 2 to the power of the ack_delay_exponent transport parameter sent by the sender of the ACK frame. Compared to simply expressing the delay as an integer, this encoding allows for a larger range of values within the same number of bytes, at the cost of lower resolution.
	AckRanges                             []AckRange    // Contains additional ranges of packets that are alternately not acknowledged (Gap) and acknowledged (ACK Range);
	ECT0, ECT1, ECNCE                     uint64        // The three ECN counts
}
