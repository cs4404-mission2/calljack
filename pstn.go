package main

import (
	"errors"
	"time"

	"github.com/jart/gosip/rtp"
	"github.com/jart/gosip/sdp"
)

type rtpHeader struct {
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

// u32 converts a byte slice to a uint32
func u32(b []byte) uint32 {
	var u uint32
	for i := 0; i < len(b); i++ {
		u = u<<8 + uint32(b[i])
	}
	return u
}

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

func (h *rtpHeader) read(b []byte) error {
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
