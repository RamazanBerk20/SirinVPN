// SPDX-License-Identifier: AGPL-3.0-only
// Uses upstream WireGuard's protocol engine. No UAPI listener or Android logger.
package main

/*
#include <stdint.h>
*/
import "C"
import (
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"strconv"
	"strings"
	"sync"
)

type tunnel struct {
	engine   *device.Device
	settings string
	probe    *probeTun
}

var lock sync.Mutex
var tunnels = map[int32]*tunnel{}
var next int32

//export sirinStart
func sirinStart(fd C.int, settings *C.char) C.int {
	lock.Lock()
	defer lock.Unlock()
	adapter, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	if err != nil {
		return -1
	}
	return start(adapter, C.GoString(settings), nil)
}

func start(adapter tun.Device, value string, probe *probeTun) C.int {
	engine := device.NewDevice(adapter, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	// The controller owns carrier changes. Delayed authenticated packets from the
	// old carrier must not roam the peer back after a reviewed endpoint handoff.
	engine.DisableSomeRoamingForBrokenMobileSemantics()
	var staged []string
	for _, line := range strings.Split(value, "\n") {
		// Open sockets without sending anything before Android protects them.
		if !strings.HasPrefix(line, "endpoint=") && !strings.HasPrefix(line, "persistent_keepalive_interval=") {
			staged = append(staged, line)
		}
	}
	if engine.IpcSet(strings.Join(staged, "\n")) != nil || engine.Up() != nil {
		engine.Close()
		return -1
	}
	next++
	tunnels[next] = &tunnel{engine, value, probe}
	return C.int(next)
}

//export sirinEndpoint
func sirinEndpoint(handle C.int, settings *C.char) C.int {
	lock.Lock()
	defer lock.Unlock()
	item := tunnels[int32(handle)]
	if item == nil {
		return 0
	}
	if item.engine.IpcSet(C.GoString(settings)) != nil {
		return 0
	}
	return 1
}

//export sirinCommit
func sirinCommit(handle C.int) C.int {
	lock.Lock()
	defer lock.Unlock()
	item := tunnels[int32(handle)]
	if item == nil {
		return 0
	}
	value := item.settings
	item.settings = ""
	if item.engine.IpcSet(value) != nil {
		return 0
	}
	return 1
}

//export sirinStop
func sirinStop(handle C.int) {
	lock.Lock()
	defer lock.Unlock()
	if item := tunnels[int32(handle)]; item != nil {
		delete(tunnels, int32(handle))
		item.engine.Close()
	}
}

//export sirinSocket
func sirinSocket(handle C.int, family C.int) C.int {
	lock.Lock()
	defer lock.Unlock()
	item := tunnels[int32(handle)]
	if item == nil {
		return -1
	}
	bind, ok := item.engine.Bind().(conn.PeekLookAtSocketFd)
	if !ok {
		return -1
	}
	var fd int
	var err error
	if family == 4 {
		fd, err = bind.PeekLookAtSocketFd4()
	} else {
		fd, err = bind.PeekLookAtSocketFd6()
	}
	if err != nil {
		return -1
	}
	return C.int(fd)
}

//export sirinStats
func sirinStats(handle C.int, rx *C.int64_t, tx *C.int64_t, handshake *C.int64_t) C.int {
	lock.Lock()
	defer lock.Unlock()
	item := tunnels[int32(handle)]
	if item == nil {
		return 0
	}
	value, err := item.engine.IpcGet()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(value, "\n") {
		name, text, _ := strings.Cut(line, "=")
		if name != "rx_bytes" && name != "tx_bytes" && name != "last_handshake_time_sec" {
			continue
		}
		number, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0
		}
		switch name {
		case "rx_bytes":
			*rx = C.int64_t(number)
		case "tx_bytes":
			*tx = C.int64_t(number)
		case "last_handshake_time_sec":
			*handshake = C.int64_t(number)
		}
	}
	return 1
}
func main() {}
