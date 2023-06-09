package wire

import (
	"bytes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
	"math"
)

var _ = Describe("PATH_STATUS frame", func() {
	Context("when parsing", func() {
		It("accepts valid PATH_Status frame", func() {
			data := encodeVarInt(pathStatusFrameType) // frame type
			data = append(data, encodeVarInt(0x1)...) // Destination Connection ID Sequence Number
			data = append(data, encodeVarInt(0x0)...) // PathStatus Sequence Number
			data = append(data, encodeVarInt(0x1)...)
			b := bytes.NewReader(data)
			frame, err := parsePathStatusFrame(b, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.DestinationConnectionIDSequenceNumber).To(BeEquivalentTo(0x1))
			Expect(frame.PathStatusSequenceNumber).To(BeEquivalentTo(0x0))
			Expect(frame.FrameType).To(BeEquivalentTo(pathStatusFrameType))
			Expect(frame.PathStatus).To(Equal(uint64(0x1)))
			Expect(b.Len()).To(BeZero())
		})
		It("PathStatus is two", func() {
			data := encodeVarInt(pathStatusFrameType) // frame type
			data = append(data, encodeVarInt(0x1)...)
			data = append(data, encodeVarInt(0x0)...)
			data = append(data, encodeVarInt(0x2)...)
			b := bytes.NewReader(data)
			frame, err := parsePathStatusFrame(b, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			Expect(frame.PathStatus).To(Equal(uint64(0x2)))
		})
		It("PathStatus is not one or two", func() {
			data := encodeVarInt(pathStatusFrameType) // frame type
			data = append(data, encodeVarInt(0x1)...)
			data = append(data, encodeVarInt(0x0)...)
			data = append(data, encodeVarInt(0x3)...)
			b := bytes.NewReader(data)
			frame, err := parsePathStatusFrame(b, protocol.Version1)
			Expect(err).To(HaveOccurred())
			var errFrame *PathStatusFrame = nil
			Expect(frame).To(Equal(errFrame))
		})

	})
	Context("when writing", func() {
		It("writes a sample frame", func() {
			frame := PathStatusFrame{PathStatus: 1, DestinationConnectionIDSequenceNumber: 1, PathStatusSequenceNumber: 1}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			testByte := quicvarint.Append(make([]byte, 0), pathStatusFrameType)
			testByte = append(testByte, 1, 1, 1)
			Expect(b).To(Equal(testByte))
		})
		It("writes a edge case frame", func() {
			frame := PathStatusFrame{PathStatus: 1, DestinationConnectionIDSequenceNumber: math.MaxUint64 >> 2, PathStatusSequenceNumber: math.MaxUint64 >> 2}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			testByte := quicvarint.Append(make([]byte, 0), pathStatusFrameType)
			testByte = quicvarint.Append(testByte, math.MaxUint64>>2)
			testByte = quicvarint.Append(testByte, math.MaxUint64>>2)
			testByte = append(testByte, 1)
			Expect(b).To(Equal(testByte))
		})
		It("has the correct length", func() {
			frame := PathStatusFrame{}
			Expect(frame.Length(protocol.Version1)).To(Equal(protocol.ByteCount(7)))
		})
	})
})
