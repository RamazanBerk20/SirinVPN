// SPDX-License-Identifier: AGPL-3.0-only
package main

/*
#include <stdint.h>
*/
import "C"
import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"golang.zx2c4.com/wireguard/tun"
	"io"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"
)

// A bounded in-memory ICMP peer. It never receives application packets, installs
// an OS route, opens a TUN, or replaces the active Android VPN interface.
type probeTun struct {
	outgoing chan []byte
	incoming chan []byte
	closed   chan struct{}
	events   chan tun.Event
	once     sync.Once
	sample   sync.Mutex
}

func newProbe() *probeTun {
	return &probeTun{outgoing: make(chan []byte, 8), incoming: make(chan []byte, 32), closed: make(chan struct{}), events: make(chan tun.Event)}
}
func (p *probeTun) File() *os.File           { return nil }
func (p *probeTun) MTU() (int, error)        { return 1420, nil }
func (p *probeTun) Name() (string, error)    { return "SirinVPN ephemeral probe", nil }
func (p *probeTun) Events() <-chan tun.Event { return p.events }
func (p *probeTun) BatchSize() int           { return 1 }
func (p *probeTun) Close() error             { p.once.Do(func() { close(p.closed); close(p.events) }); return nil }
func (p *probeTun) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-p.closed:
		return 0, io.EOF
	case packet := <-p.outgoing:
		if len(buffers) == 0 || len(sizes) == 0 || offset < 0 || len(buffers[0])-offset < len(packet) {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(buffers[0][offset:], packet)
		return 1, nil
	}
}
func (p *probeTun) Write(buffers [][]byte, offset int) (int, error) {
	for _, buffer := range buffers {
		if offset < 0 || offset > len(buffer) || len(buffer)-offset > 1420 {
			continue
		}
		packet := append([]byte(nil), buffer[offset:]...)
		select {
		case <-p.closed:
			return 0, io.EOF
		case p.incoming <- packet:
		default:
		}
	}
	return len(buffers), nil
}
func checksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) > 1 {
		sum += uint32(binary.BigEndian.Uint16(packet))
		packet = packet[2:]
	}
	if len(packet) == 1 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func echo(source, destination [4]byte, nonce []byte, sequence uint16) []byte {
	packet := make([]byte, 60)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 1
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:], 0x4000)
	copy(packet[12:], source[:])
	copy(packet[16:], destination[:])
	packet[20] = 8
	copy(packet[24:26], nonce[:2])
	binary.BigEndian.PutUint16(packet[26:], sequence)
	copy(packet[28:], nonce)
	binary.BigEndian.PutUint16(packet[22:], checksum(packet[20:]))
	binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20]))
	return packet
}
func reply(packet []byte, source, destination [4]byte, nonce []byte) (int, bool) {
	if len(packet) != 60 || packet[0] != 0x45 || packet[9] != 1 || binary.BigEndian.Uint16(packet[2:]) != 60 || binary.BigEndian.Uint16(packet[6:])&0x3fff != 0 || checksum(packet[:20]) != 0 || checksum(packet[20:]) != 0 {
		return 0, false
	}
	if !bytes.Equal(packet[12:16], destination[:]) || !bytes.Equal(packet[16:20], source[:]) || packet[20] != 0 || packet[21] != 0 || !bytes.Equal(packet[24:26], nonce[:2]) || !bytes.Equal(packet[28:], nonce) {
		return 0, false
	}
	sequence := int(binary.BigEndian.Uint16(packet[26:]))
	return sequence, sequence < 8
}

//export sirinProbeStart
func sirinProbeStart(settings *C.char) C.int {
	lock.Lock()
	defer lock.Unlock()
	probe := newProbe()
	return start(probe, C.GoString(settings), probe)
}

//export sirinProbeSample
func sirinProbeSample(handle C.int, sourceText, destinationText *C.char, received, latency, jitter *C.int64_t) C.int {
	lock.Lock()
	item := tunnels[int32(handle)]
	lock.Unlock()
	if item == nil || item.probe == nil {
		return 0
	}
	source, err := netip.ParseAddr(C.GoString(sourceText))
	if err != nil || !source.Is4() {
		return 0
	}
	destination, err := netip.ParseAddr(C.GoString(destinationText))
	if err != nil || !destination.Is4() {
		return 0
	}
	p := item.probe
	p.sample.Lock()
	defer p.sample.Unlock()
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return 0
	}
	sent := make([]time.Time, 8)
	samples := make([]float64, 0, 8)
	seen := [8]bool{}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(4 * time.Second)
	defer timeout.Stop()
	index := 0
	for {
		select {
		case <-p.closed:
			return 0
		case <-ticker.C:
			if index < 8 {
				packet := echo(source.As4(), destination.As4(), nonce, uint16(index))
				sent[index] = time.Now()
				index++
				select {
				case p.outgoing <- packet:
				case <-p.closed:
					return 0
				default:
				}
			}
		case packet := <-p.incoming:
			sequence, ok := reply(packet, source.As4(), destination.As4(), nonce)
			if ok && !seen[sequence] && !sent[sequence].IsZero() {
				seen[sequence] = true
				samples = append(samples, float64(time.Since(sent[sequence]).Microseconds()))
				if len(samples) == 8 {
					goto complete
				}
			}
		case <-timeout.C:
			goto complete
		}
	}
complete:
	if len(samples) == 0 {
		return 0
	}
	var mean, variance float64
	for _, value := range samples {
		mean += value
	}
	mean /= float64(len(samples))
	for _, value := range samples {
		variance += (value - mean) * (value - mean)
	}
	*received = C.int64_t(len(samples))
	*latency = C.int64_t(mean)
	*jitter = C.int64_t(math.Sqrt(variance / float64(len(samples))))
	return 1
}
