package ackhandler

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Received Packet Tracker", func() {
	var (
		singlePathTracker *singlePathTracker
		multiPathTracker  *multiPathTracker
		rttStats          *utils.RTTStats
	)

	BeforeEach(func() {
		rttStats = &utils.RTTStats{}
		singlePathTracker = newReceivedPacketTracker(rttStats, utils.DefaultLogger)
		multiPathTracker = newReceivedMultiPathPacketTracker(rttStats, utils.DefaultLogger)
	})

	Context("accepting packets", func() {
		It("saves the time when each packet arrived", func() {
			Expect(singlePathTracker.ReceivedPacket(protocol.PacketNumber(3), protocol.ECNNon, time.Now(), true)).To(Succeed())
			Expect(singlePathTracker.largestObservedReceivedTime).To(BeTemporally("~", time.Now(), 10*time.Millisecond))

			Expect(multiPathTracker.ReceivedMPPacket(protocol.PacketNumber(3), protocol.ECNNon, time.Now(), true)).To(Succeed())
			Expect(multiPathTracker.largestObservedReceivedTime).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("updates the largestObserved and the largestObservedReceivedTime", func() {
			now := time.Now()
			singlePathTracker.largestObserved = 3
			singlePathTracker.largestObservedReceivedTime = now.Add(-1 * time.Second)
			Expect(singlePathTracker.ReceivedPacket(5, protocol.ECNNon, now, true)).To(Succeed())
			Expect(singlePathTracker.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(singlePathTracker.largestObservedReceivedTime).To(Equal(now))

			multiPathTracker.largestObserved = 3
			multiPathTracker.largestObservedReceivedTime = now.Add(-1 * time.Second)
			Expect(multiPathTracker.ReceivedMPPacket(5, protocol.ECNNon, now, true)).To(Succeed())
			Expect(multiPathTracker.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(multiPathTracker.largestObservedReceivedTime).To(Equal(now))
		})

		It("doesn't update the largestObserved and the largestObservedReceivedTime for a belated packet", func() {
			now := time.Now()
			timestamp := now.Add(-1 * time.Second)
			singlePathTracker.largestObserved = 5
			singlePathTracker.largestObservedReceivedTime = timestamp
			Expect(singlePathTracker.ReceivedPacket(4, protocol.ECNNon, now, true)).To(Succeed())
			Expect(singlePathTracker.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(singlePathTracker.largestObservedReceivedTime).To(Equal(timestamp))

			multiPathTracker.largestObserved = 5
			multiPathTracker.largestObservedReceivedTime = timestamp
			Expect(multiPathTracker.ReceivedMPPacket(4, protocol.ECNNon, now, true)).To(Succeed())
			Expect(multiPathTracker.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(multiPathTracker.largestObservedReceivedTime).To(Equal(timestamp))
		})
	})

	Context("ACKs", func() {
		Context("queueing ACKs", func() {
			receiveAndAck10Packets := func() {
				for i := 1; i <= 10; i++ {
					Expect(singlePathTracker.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, time.Time{}, true)).To(Succeed())
				}
				Expect(singlePathTracker.GetAckFrame(true)).ToNot(BeNil())
				Expect(singlePathTracker.ackQueued).To(BeFalse())
			}

			It("always queues an ACK for the first packet", func() {
				Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(singlePathTracker.ackQueued).To(BeTrue())
				Expect(singlePathTracker.GetAlarmTimeout()).To(BeZero())
				Expect(singlePathTracker.GetAckFrame(true).DelayTime).To(BeNumerically("~", 0, time.Second))
			})

			It("works with packet number 0", func() {
				Expect(singlePathTracker.ReceivedPacket(0, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(singlePathTracker.ackQueued).To(BeTrue())
				Expect(singlePathTracker.GetAlarmTimeout()).To(BeZero())
				Expect(singlePathTracker.GetAckFrame(true).DelayTime).To(BeNumerically("~", 0, time.Second))
			})

			It("sets ECN flags", func() {
				Expect(singlePathTracker.ReceivedPacket(0, protocol.ECT0, time.Now(), true)).To(Succeed())
				pn := protocol.PacketNumber(1)
				for i := 0; i < 2; i++ {
					Expect(singlePathTracker.ReceivedPacket(pn, protocol.ECT1, time.Now(), true)).To(Succeed())
					pn++
				}
				for i := 0; i < 3; i++ {
					Expect(singlePathTracker.ReceivedPacket(pn, protocol.ECNCE, time.Now(), true)).To(Succeed())
					pn++
				}
				ack := singlePathTracker.GetAckFrame(false)
				Expect(ack.ECT0).To(BeEquivalentTo(1))
				Expect(ack.ECT1).To(BeEquivalentTo(2))
				Expect(ack.ECNCE).To(BeEquivalentTo(3))
			})

			It("queues an ACK for every second ack-eliciting packet", func() {
				receiveAndAck10Packets()
				p := protocol.PacketNumber(11)
				for i := 0; i <= 20; i++ {
					Expect(singlePathTracker.ReceivedPacket(p, protocol.ECNNon, time.Time{}, true)).To(Succeed())
					Expect(singlePathTracker.ackQueued).To(BeFalse())
					p++
					Expect(singlePathTracker.ReceivedPacket(p, protocol.ECNNon, time.Time{}, true)).To(Succeed())
					Expect(singlePathTracker.ackQueued).To(BeTrue())
					p++
					// dequeue the ACK frame
					Expect(singlePathTracker.GetAckFrame(true)).ToNot(BeNil())
				}
			})

			It("resets the counter when a non-queued ACK frame is generated", func() {
				receiveAndAck10Packets()
				rcvTime := time.Now()
				Expect(singlePathTracker.ReceivedPacket(11, protocol.ECNNon, rcvTime, true)).To(Succeed())
				Expect(singlePathTracker.GetAckFrame(false)).ToNot(BeNil())
				Expect(singlePathTracker.ReceivedPacket(12, protocol.ECNNon, rcvTime, true)).To(Succeed())
				Expect(singlePathTracker.GetAckFrame(true)).To(BeNil())
				Expect(singlePathTracker.ReceivedPacket(13, protocol.ECNNon, rcvTime, true)).To(Succeed())
				Expect(singlePathTracker.GetAckFrame(false)).ToNot(BeNil())
			})

			It("only sets the timer when receiving a ack-eliciting packets", func() {
				receiveAndAck10Packets()
				Expect(singlePathTracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), false)).To(Succeed())
				Expect(singlePathTracker.ackQueued).To(BeFalse())
				Expect(singlePathTracker.GetAlarmTimeout()).To(BeZero())
				rcvTime := time.Now().Add(10 * time.Millisecond)
				Expect(singlePathTracker.ReceivedPacket(12, protocol.ECNNon, rcvTime, true)).To(Succeed())
				Expect(singlePathTracker.ackQueued).To(BeFalse())
				Expect(singlePathTracker.GetAlarmTimeout()).To(Equal(rcvTime.Add(protocol.MaxAckDelay)))
			})

			It("queues an ACK if it was reported missing before", func() {
				receiveAndAck10Packets()
				Expect(singlePathTracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(singlePathTracker.ReceivedPacket(13, protocol.ECNNon, time.Now(), true)).To(Succeed())
				ack := singlePathTracker.GetAckFrame(true) // ACK: 1-11 and 13, missing: 12
				Expect(ack).ToNot(BeNil())
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(singlePathTracker.ackQueued).To(BeFalse())
				Expect(singlePathTracker.ReceivedPacket(12, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(singlePathTracker.ackQueued).To(BeTrue())
			})

			It("doesn't recognize in-order packets as out-of-order after raising the threshold", func() {
				receiveAndAck10Packets()
				Expect(singlePathTracker.lastAck.LargestAcked()).To(Equal(protocol.PacketNumber(10)))
				Expect(singlePathTracker.ackQueued).To(BeFalse())
				singlePathTracker.IgnoreBelow(11)
				Expect(singlePathTracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(singlePathTracker.GetAckFrame(true)).To(BeNil())
			})

			It("recognizes out-of-order packets after raising the threshold", func() {
				receiveAndAck10Packets()
				Expect(singlePathTracker.lastAck.LargestAcked()).To(Equal(protocol.PacketNumber(10)))
				Expect(singlePathTracker.ackQueued).To(BeFalse())
				singlePathTracker.IgnoreBelow(11)
				Expect(singlePathTracker.ReceivedPacket(12, protocol.ECNNon, time.Now(), true)).To(Succeed())
				ack := singlePathTracker.GetAckFrame(true)
				Expect(ack).ToNot(BeNil())
				Expect(ack.AckRanges).To(Equal([]wire.AckRange{{Smallest: 12, Largest: 12}}))
			})

			It("doesn't queue an ACK if for non-ack-eliciting packets arriving out-of-order", func() {
				receiveAndAck10Packets()
				Expect(singlePathTracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(singlePathTracker.GetAckFrame(true)).To(BeNil())
				Expect(singlePathTracker.ReceivedPacket(13, protocol.ECNNon, time.Now(), false)).To(Succeed()) // receive a non-ack-eliciting packet out-of-order
				Expect(singlePathTracker.GetAckFrame(true)).To(BeNil())
			})

			It("doesn't queue an ACK if packets arrive out-of-order, but haven't been acknowledged yet", func() {
				receiveAndAck10Packets()
				Expect(singlePathTracker.lastAck).ToNot(BeNil())
				Expect(singlePathTracker.ReceivedPacket(12, protocol.ECNNon, time.Now(), false)).To(Succeed())
				Expect(singlePathTracker.GetAckFrame(true)).To(BeNil())
				// 11 is received out-of-order, but this hasn't been reported in an ACK frame yet
				Expect(singlePathTracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(singlePathTracker.GetAckFrame(true)).To(BeNil())
			})
		})

		Context("ACK generation", func() {
			It("generates an ACK for an ack-eliciting packet, if no ACK is queued yet", func() {
				Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
				// The first packet is always acknowledged.
				Expect(singlePathTracker.GetAckFrame(true)).ToNot(BeNil())
			})

			It("doesn't generate ACK for a non-ack-eliciting packet, if no ACK is queued yet", func() {
				Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
				// The first packet is always acknowledged.
				Expect(singlePathTracker.GetAckFrame(true)).ToNot(BeNil())

				Expect(singlePathTracker.ReceivedPacket(2, protocol.ECNNon, time.Now(), false)).To(Succeed())
				Expect(singlePathTracker.GetAckFrame(false)).To(BeNil())
				Expect(singlePathTracker.ReceivedPacket(3, protocol.ECNNon, time.Now(), true)).To(Succeed())
				ack := singlePathTracker.GetAckFrame(false)
				Expect(ack).ToNot(BeNil())
				Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(3)))
			})

			Context("for queued ACKs", func() {
				BeforeEach(func() {
					singlePathTracker.ackQueued = true
				})

				It("generates a simple ACK frame", func() {
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(singlePathTracker.ReceivedPacket(2, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(2)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("generates an ACK for packet number 0", func() {
					Expect(singlePathTracker.ReceivedPacket(0, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("sets the delay time", func() {
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(singlePathTracker.ReceivedPacket(2, protocol.ECNNon, time.Now().Add(-1337*time.Millisecond), true)).To(Succeed())
					ack := singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.DelayTime).To(BeNumerically("~", 1337*time.Millisecond, 50*time.Millisecond))
				})

				It("uses a 0 delay time if the delay would be negative", func() {
					Expect(singlePathTracker.ReceivedPacket(0, protocol.ECNNon, time.Now().Add(time.Hour), true)).To(Succeed())
					ack := singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.DelayTime).To(BeZero())
				})

				It("saves the last sent ACK", func() {
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(singlePathTracker.lastAck).To(Equal(ack))
					Expect(singlePathTracker.ReceivedPacket(2, protocol.ECNNon, time.Now(), true)).To(Succeed())
					singlePathTracker.ackQueued = true
					ack = singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(singlePathTracker.lastAck).To(Equal(ack))
				})

				It("generates an ACK frame with missing packets", func() {
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(singlePathTracker.ReceivedPacket(4, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(4)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(ack.AckRanges).To(Equal([]wire.AckRange{
						{Smallest: 4, Largest: 4},
						{Smallest: 1, Largest: 1},
					}))
				})

				It("generates an ACK for packet number 0 and other packets", func() {
					Expect(singlePathTracker.ReceivedPacket(0, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(singlePathTracker.ReceivedPacket(3, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(3)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.AckRanges).To(Equal([]wire.AckRange{
						{Smallest: 3, Largest: 3},
						{Smallest: 0, Largest: 1},
					}))
				})

				It("errors when called with an old packet", func() {
					singlePathTracker.IgnoreBelow(7)
					Expect(singlePathTracker.IsPotentiallyDuplicate(4)).To(BeTrue())
					Expect(singlePathTracker.ReceivedPacket(4, protocol.ECNNon, time.Now(), true)).To(MatchError("recevedPacketTracker BUG: ReceivedPacket called for old / duplicate packet 4"))
				})

				It("deletes packets from the packetHistory when a lower limit is set", func() {
					for i := 1; i <= 12; i++ {
						Expect(singlePathTracker.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, time.Now(), true)).To(Succeed())
					}
					singlePathTracker.IgnoreBelow(7)
					// check that the packets were deleted from the receivedPacketHistory by checking the values in an ACK frame
					ack := singlePathTracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(12)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(7)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("resets all counters needed for the ACK queueing decision when sending an ACK", func() {
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					singlePathTracker.ackAlarm = time.Now().Add(-time.Minute)
					Expect(singlePathTracker.GetAckFrame(true)).ToNot(BeNil())
					Expect(singlePathTracker.GetAlarmTimeout()).To(BeZero())
					Expect(singlePathTracker.ackElicitingPacketsReceivedSinceLastAck).To(BeZero())
					Expect(singlePathTracker.ackQueued).To(BeFalse())
				})

				It("doesn't generate an ACK when none is queued and the timer is not set", func() {
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					singlePathTracker.ackQueued = false
					singlePathTracker.ackAlarm = time.Time{}
					Expect(singlePathTracker.GetAckFrame(true)).To(BeNil())
				})

				It("doesn't generate an ACK when none is queued and the timer has not yet expired", func() {
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					singlePathTracker.ackQueued = false
					singlePathTracker.ackAlarm = time.Now().Add(time.Minute)
					Expect(singlePathTracker.GetAckFrame(true)).To(BeNil())
				})

				It("generates an ACK when the timer has expired", func() {
					Expect(singlePathTracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					singlePathTracker.ackQueued = false
					singlePathTracker.ackAlarm = time.Now().Add(-time.Minute)
					Expect(singlePathTracker.GetAckFrame(true)).ToNot(BeNil())
				})
			})
		})
	})

	Context("ACK_MPs", func() {
		Context("queueing ACKs", func() {
			receiveAndAck10Packets := func() {
				for i := 1; i <= 10; i++ {
					Expect(multiPathTracker.ReceivedMPPacket(protocol.PacketNumber(i), protocol.ECNNon, time.Time{}, true)).To(Succeed())
				}
				Expect(multiPathTracker.GetAckMPFrame(true)).ToNot(BeNil())
				Expect(multiPathTracker.ackQueued).To(BeFalse())
			}

			It("always queues an ACK for the first packet", func() {
				Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(multiPathTracker.ackQueued).To(BeTrue())
				Expect(multiPathTracker.GetAlarmTimeout()).To(BeZero())
				Expect(multiPathTracker.GetAckMPFrame(true).DelayTime).To(BeNumerically("~", 0, time.Second))
			})

			It("works with packet number 0", func() {
				Expect(multiPathTracker.ReceivedMPPacket(0, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(multiPathTracker.ackQueued).To(BeTrue())
				Expect(multiPathTracker.GetAlarmTimeout()).To(BeZero())
				Expect(multiPathTracker.GetAckMPFrame(true).DelayTime).To(BeNumerically("~", 0, time.Second))
			})

			It("sets ECN flags", func() {
				Expect(multiPathTracker.ReceivedMPPacket(0, protocol.ECT0, time.Now(), true)).To(Succeed())
				pn := protocol.PacketNumber(1)
				for i := 0; i < 2; i++ {
					Expect(multiPathTracker.ReceivedMPPacket(pn, protocol.ECT1, time.Now(), true)).To(Succeed())
					pn++
				}
				for i := 0; i < 3; i++ {
					Expect(multiPathTracker.ReceivedMPPacket(pn, protocol.ECNCE, time.Now(), true)).To(Succeed())
					pn++
				}
				ack := multiPathTracker.GetAckMPFrame(false)
				Expect(ack.ECT0).To(BeEquivalentTo(1))
				Expect(ack.ECT1).To(BeEquivalentTo(2))
				Expect(ack.ECNCE).To(BeEquivalentTo(3))
			})

			It("queues an ACK for every second ack-eliciting packet", func() {
				receiveAndAck10Packets()
				p := protocol.PacketNumber(11)
				for i := 0; i <= 20; i++ {
					Expect(multiPathTracker.ReceivedMPPacket(p, protocol.ECNNon, time.Time{}, true)).To(Succeed())
					Expect(multiPathTracker.ackQueued).To(BeFalse())
					p++
					Expect(multiPathTracker.ReceivedMPPacket(p, protocol.ECNNon, time.Time{}, true)).To(Succeed())
					Expect(multiPathTracker.ackQueued).To(BeTrue())
					p++
					// dequeue the ACK frame
					Expect(multiPathTracker.GetAckMPFrame(true)).ToNot(BeNil())
				}
			})

			It("resets the counter when a non-queued ACK frame is generated", func() {
				receiveAndAck10Packets()
				rcvTime := time.Now()
				Expect(multiPathTracker.ReceivedMPPacket(11, protocol.ECNNon, rcvTime, true)).To(Succeed())
				Expect(multiPathTracker.GetAckMPFrame(false)).ToNot(BeNil())
				Expect(multiPathTracker.ReceivedMPPacket(12, protocol.ECNNon, rcvTime, true)).To(Succeed())
				Expect(multiPathTracker.GetAckMPFrame(true)).To(BeNil())
				Expect(multiPathTracker.ReceivedMPPacket(13, protocol.ECNNon, rcvTime, true)).To(Succeed())
				Expect(multiPathTracker.GetAckMPFrame(false)).ToNot(BeNil())
			})

			It("only sets the timer when receiving a ack-eliciting packets", func() {
				receiveAndAck10Packets()
				Expect(multiPathTracker.ReceivedMPPacket(11, protocol.ECNNon, time.Now(), false)).To(Succeed())
				Expect(multiPathTracker.ackQueued).To(BeFalse())
				Expect(multiPathTracker.GetAlarmTimeout()).To(BeZero())
				rcvTime := time.Now().Add(10 * time.Millisecond)
				Expect(multiPathTracker.ReceivedMPPacket(12, protocol.ECNNon, rcvTime, true)).To(Succeed())
				Expect(multiPathTracker.ackQueued).To(BeFalse())
				Expect(multiPathTracker.GetAlarmTimeout()).To(Equal(rcvTime.Add(protocol.MaxAckDelay)))
			})

			It("queues an ACK if it was reported missing before", func() {
				receiveAndAck10Packets()
				Expect(multiPathTracker.ReceivedMPPacket(11, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(multiPathTracker.ReceivedMPPacket(13, protocol.ECNNon, time.Now(), true)).To(Succeed())
				ack := multiPathTracker.GetAckMPFrame(true) // ACK: 1-11 and 13, missing: 12
				Expect(ack).ToNot(BeNil())
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(multiPathTracker.ackQueued).To(BeFalse())
				Expect(multiPathTracker.ReceivedMPPacket(12, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(multiPathTracker.ackQueued).To(BeTrue())
			})

			It("doesn't recognize in-order packets as out-of-order after raising the threshold", func() {
				receiveAndAck10Packets()
				Expect(multiPathTracker.lastAck.LargestAcked()).To(Equal(protocol.PacketNumber(10)))
				Expect(multiPathTracker.ackQueued).To(BeFalse())
				multiPathTracker.IgnoreBelow(11)
				Expect(multiPathTracker.ReceivedMPPacket(11, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(multiPathTracker.GetAckMPFrame(true)).To(BeNil())
			})

			It("recognizes out-of-order packets after raising the threshold", func() {
				receiveAndAck10Packets()
				Expect(multiPathTracker.lastAck.LargestAcked()).To(Equal(protocol.PacketNumber(10)))
				Expect(multiPathTracker.ackQueued).To(BeFalse())
				multiPathTracker.IgnoreBelow(11)
				Expect(multiPathTracker.ReceivedMPPacket(12, protocol.ECNNon, time.Now(), true)).To(Succeed())
				ack := multiPathTracker.GetAckMPFrame(true)
				Expect(ack).ToNot(BeNil())
				Expect(ack.AckRanges).To(Equal([]wire.AckRange{{Smallest: 12, Largest: 12}}))
			})

			It("doesn't queue an ACK if for non-ack-eliciting packets arriving out-of-order", func() {
				receiveAndAck10Packets()
				Expect(multiPathTracker.ReceivedMPPacket(11, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(multiPathTracker.GetAckMPFrame(true)).To(BeNil())
				Expect(multiPathTracker.ReceivedMPPacket(13, protocol.ECNNon, time.Now(), false)).To(Succeed()) // receive a non-ack-eliciting packet out-of-order
				Expect(multiPathTracker.GetAckMPFrame(true)).To(BeNil())
			})

			It("doesn't queue an ACK if packets arrive out-of-order, but haven't been acknowledged yet", func() {
				receiveAndAck10Packets()
				Expect(multiPathTracker.lastAck).ToNot(BeNil())
				Expect(multiPathTracker.ReceivedMPPacket(12, protocol.ECNNon, time.Now(), false)).To(Succeed())
				Expect(multiPathTracker.GetAckMPFrame(true)).To(BeNil())
				// 11 is received out-of-order, but this hasn't been reported in an ACK frame yet
				Expect(multiPathTracker.ReceivedMPPacket(11, protocol.ECNNon, time.Now(), true)).To(Succeed())
				Expect(multiPathTracker.GetAckMPFrame(true)).To(BeNil())
			})
		})

		Context("ACK generation", func() {
			It("generates an ACK for an ack-eliciting packet, if no ACK is queued yet", func() {
				Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
				// The first packet is always acknowledged.
				Expect(multiPathTracker.GetAckMPFrame(true)).ToNot(BeNil())
			})

			It("doesn't generate ACK for a non-ack-eliciting packet, if no ACK is queued yet", func() {
				Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
				// The first packet is always acknowledged.
				Expect(multiPathTracker.GetAckMPFrame(true)).ToNot(BeNil())

				Expect(multiPathTracker.ReceivedMPPacket(2, protocol.ECNNon, time.Now(), false)).To(Succeed())
				Expect(multiPathTracker.GetAckMPFrame(false)).To(BeNil())
				Expect(multiPathTracker.ReceivedMPPacket(3, protocol.ECNNon, time.Now(), true)).To(Succeed())
				ack := multiPathTracker.GetAckMPFrame(false)
				Expect(ack).ToNot(BeNil())
				Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(3)))
			})

			Context("for queued ACKs", func() {
				BeforeEach(func() {
					singlePathTracker.ackQueued = true
				})

				It("generates a simple ACK frame", func() {
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(multiPathTracker.ReceivedMPPacket(2, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(2)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("generates an ACK for packet number 0", func() {
					Expect(multiPathTracker.ReceivedMPPacket(0, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("sets the delay time", func() {
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(multiPathTracker.ReceivedMPPacket(2, protocol.ECNNon, time.Now().Add(-1337*time.Millisecond), true)).To(Succeed())
					ack := multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.DelayTime).To(BeNumerically("~", 1337*time.Millisecond, 50*time.Millisecond))
				})

				It("uses a 0 delay time if the delay would be negative", func() {
					Expect(multiPathTracker.ReceivedMPPacket(0, protocol.ECNNon, time.Now().Add(time.Hour), true)).To(Succeed())
					ack := multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.DelayTime).To(BeZero())
				})

				It("saves the last sent ACK", func() {
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(multiPathTracker.lastAck).To(Equal(ack))
					Expect(multiPathTracker.ReceivedMPPacket(2, protocol.ECNNon, time.Now(), true)).To(Succeed())
					multiPathTracker.ackQueued = true
					ack = multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(multiPathTracker.lastAck).To(Equal(ack))
				})

				It("generates an ACK frame with missing packets", func() {
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(multiPathTracker.ReceivedMPPacket(4, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(4)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(ack.AckRanges).To(Equal([]wire.AckRange{
						{Smallest: 4, Largest: 4},
						{Smallest: 1, Largest: 1},
					}))
				})

				It("generates an ACK for packet number 0 and other packets", func() {
					Expect(multiPathTracker.ReceivedMPPacket(0, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					Expect(multiPathTracker.ReceivedMPPacket(3, protocol.ECNNon, time.Now(), true)).To(Succeed())
					ack := multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(3)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.AckRanges).To(Equal([]wire.AckRange{
						{Smallest: 3, Largest: 3},
						{Smallest: 0, Largest: 1},
					}))
				})

				It("errors when called with an old packet", func() {
					multiPathTracker.IgnoreBelow(7)
					Expect(multiPathTracker.IsPotentiallyDuplicate(4)).To(BeTrue())
					Expect(multiPathTracker.ReceivedMPPacket(4, protocol.ECNNon, time.Now(), true)).To(MatchError("recevedPacketTracker BUG: ReceivedPacket called for old / duplicate packet 4"))
				})

				It("deletes packets from the packetHistory when a lower limit is set", func() {
					for i := 1; i <= 12; i++ {
						Expect(multiPathTracker.ReceivedMPPacket(protocol.PacketNumber(i), protocol.ECNNon, time.Now(), true)).To(Succeed())
					}
					multiPathTracker.IgnoreBelow(7)
					// check that the packets were deleted from the receivedPacketHistory by checking the values in an ACK frame
					ack := multiPathTracker.GetAckMPFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(12)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(7)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("resets all counters needed for the ACK queueing decision when sending an ACK", func() {
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					multiPathTracker.ackAlarm = time.Now().Add(-time.Minute)
					Expect(multiPathTracker.GetAckMPFrame(true)).ToNot(BeNil())
					Expect(multiPathTracker.GetAlarmTimeout()).To(BeZero())
					Expect(multiPathTracker.ackElicitingPacketsReceivedSinceLastAck).To(BeZero())
					Expect(multiPathTracker.ackQueued).To(BeFalse())
				})

				It("doesn't generate an ACK when none is queued and the timer is not set", func() {
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					multiPathTracker.ackQueued = false
					multiPathTracker.ackAlarm = time.Time{}
					Expect(multiPathTracker.GetAckMPFrame(true)).To(BeNil())
				})

				It("doesn't generate an ACK when none is queued and the timer has not yet expired", func() {
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					multiPathTracker.ackQueued = false
					multiPathTracker.ackAlarm = time.Now().Add(time.Minute)
					Expect(multiPathTracker.GetAckMPFrame(true)).To(BeNil())
				})

				It("generates an ACK when the timer has expired", func() {
					Expect(multiPathTracker.ReceivedMPPacket(1, protocol.ECNNon, time.Now(), true)).To(Succeed())
					multiPathTracker.ackQueued = false
					multiPathTracker.ackAlarm = time.Now().Add(-time.Minute)
					Expect(multiPathTracker.GetAckMPFrame(true)).ToNot(BeNil())
				})
			})
		})
	})
})
