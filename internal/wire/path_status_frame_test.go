package wire

import (
	"bytes"
	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
})
