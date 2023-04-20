package wire

import "golang.org/x/exp/utf8string"

// A PathAbandonFrame as described by draft-ietf-quic-multipath (version 4)
type PathAbandonFrame struct {
	DestinationConnectionIDSequenceNumber uint64            // Destination Connection ID Sequence Number: The sequence number of the Destination Connection ID used by the receiver of the frame to send packets over the path to abandon
	ErrorCode                             uint64            // A variable-length integer that indicates the reason for abandoning this path
	ReasonPhraseLength                    uint64            // A variable-length integer specifying the length of the reason phrase in bytes. Because an PATH_ABANDON frame cannot be split between packets, any limits on packet size will also limit the space available for a reason phrase
	ReasonPhrase                          utf8string.String // Additional diagnostic information for the closure.This can be zero length if the sender chooses not to give details beyond the Error Code value. This SHOULD be a UTF-8 encoded string, though the frame does not carry information, such as language tags, that would aid comprehension by any entity 	other than the one that created the text.

	/*
		PATH_ABANDON frames SHOULD be acknowledged. If a packet containing a PATH_ABANDON frame is considered lost, the peer SHOULD repeat it.
	*/
}
