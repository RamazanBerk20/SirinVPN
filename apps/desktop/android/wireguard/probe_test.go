package main

import (
	"encoding/binary"
	"encoding/hex"
	"golang.zx2c4.com/wireguard/device"
	"strings"
	"testing"
)

func TestProbeRejectsUnrelatedAndMalformedTraffic(t *testing.T) {
	source, destination := [4]byte{10, 77, 1, 2}, [4]byte{10, 77, 0, 1}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	packet := echo(source, destination, nonce, 3)
	if _, ok := reply(packet, source, destination, nonce); ok {
		t.Fatal("Accepted outgoing request as a reply")
	}
	packet[20] = 0
	copy(packet[12:16], destination[:])
	copy(packet[16:20], source[:])
	packet[10] = 0
	packet[11] = 0
	packet[22] = 0
	packet[23] = 0
	binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[22:], checksum(packet[20:]))
	if sequence, ok := reply(packet, source, destination, nonce); !ok || sequence != 3 {
		t.Fatal("Rejected a complete authenticated echo")
	}
	for length := 0; length < len(packet); length++ {
		if _, ok := reply(packet[:length], source, destination, nonce); ok {
			t.Fatal("Accepted truncated packet")
		}
	}
	for offset := range packet {
		changed := append([]byte(nil), packet...)
		changed[offset] ^= 1
		if _, ok := reply(changed, source, destination, nonce); ok {
			t.Fatal("Accepted modified packet")
		}
	}
	other := append([]byte(nil), nonce...)
	other[5] ^= 1
	if _, ok := reply(packet, source, destination, other); ok {
		t.Fatal("Accepted another sample's echo")
	}
}

func TestDelayedPacketsCannotUndoControllerEndpoint(t *testing.T) {
	key := device.NoisePublicKey{9}
	peer := "public_key=" + hex.EncodeToString(key[:]) + "\n"
	handle := start(newProbe(), "private_key="+strings.Repeat("01", 32)+"\nreplace_peers=true\n"+peer+"endpoint=127.0.0.1:51820\n", nil)
	if handle < 0 {
		t.Fatal("Could not create engine")
	}
	defer sirinStop(handle)
	if sirinCommit(handle) != 1 {
		t.Fatal("Could not commit protected configuration")
	}
	engine := tunnels[int32(handle)].engine
	old, _ := engine.Bind().ParseEndpoint("127.0.0.1:51820")
	if err := engine.IpcSet(peer + "endpoint=127.0.0.1:51825\n"); err != nil {
		t.Fatal(err)
	}
	engine.LookupPeer(key).SetEndpointFromPacket(old)
	actual, err := engine.IpcGet()
	if err != nil || !strings.Contains(actual, "endpoint=127.0.0.1:51825\n") {
		t.Fatal("A packet undid the controller's carrier change")
	}
}
