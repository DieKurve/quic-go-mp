package wire

import (
	"bytes"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
	"io"
)

// A PathAbandonFrame as described by draft-ietf-quic-multipath (version 4)
type PathAbandonFrame struct {
	FrameType                             uint64
	DestinationConnectionIDSequenceNumber uint64 // Destination Connection ID Sequence Number: The sequence number of the Destination Connection ID used by the receiver of the frame to send packets over the path to abandon
	ErrorCode                             uint64 // A variable-length integer that indicates the reason for abandoning this path
	ReasonPhrase                          string // Additional diagnostic information for the closure.This can be zero length if the sender chooses not to give details beyond the Error Code value. This SHOULD be a UTF-8 encoded string, though the frame does not carry information, such as language tags, that would aid comprehension by any entity 	other than the one that created the text.

	/*
		PATH_ABANDON frames SHOULD be acknowledged. If a packet containing a PATH_ABANDON frame is considered lost, the peer SHOULD repeat it.
	*/
}

func parsePathAbandonFrame(r *bytes.Reader, _ protocol.VersionNumber) (*PathAbandonFrame, error) {
	f := &PathAbandonFrame{}
	errorCode, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	f.ErrorCode = errorCode

	frameType, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}

	f.FrameType = frameType

	desIDSeqNum, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	f.DestinationConnectionIDSequenceNumber = desIDSeqNum

	var reasonPhraseLen uint64
	reasonPhraseLen, err = quicvarint.Read(r)

	if err != nil {
		return nil, err
	}

	if int(reasonPhraseLen) > r.Len() {
		return nil, io.EOF
	}
	reasonPhrase := make([]byte, reasonPhraseLen)
	if _, err := io.ReadFull(r, reasonPhrase); err != nil {
		// this should never happen, since we already checked the reasonPhraseLen earlier
		return nil, err
	}
	f.ReasonPhrase = string(reasonPhrase)
	return f, nil
}

func (f *PathAbandonFrame) Append(b []byte, verNum protocol.VersionNumber) ([]byte, error) {
	b = quicvarint.Append(b, pathAbandonFrameType)
	b = quicvarint.Append(b, f.DestinationConnectionIDSequenceNumber)
	b = quicvarint.Append(b, f.ErrorCode)
	b = quicvarint.Append(b, f.FrameType)
	b = quicvarint.Append(b, uint64(len(f.ReasonPhrase)))
	b = append(b, []byte(f.ReasonPhrase)...)
	return b, nil
}

// Length of a written frame
func (f *PathAbandonFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	length := 1 + quicvarint.Len(f.DestinationConnectionIDSequenceNumber) + quicvarint.Len(f.ErrorCode) + quicvarint.Len(uint64(len(f.ReasonPhrase))) + protocol.ByteCount(len(f.ReasonPhrase)) + quicvarint.Len(f.FrameType)
	return length
}
