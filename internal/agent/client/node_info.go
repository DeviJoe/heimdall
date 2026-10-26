package client

import (
	"Heimdall/api/gen/agentv1"
	"net"
	"os"
	"runtime"
	"sort"
)

func nodeInfo() *agentv1.NodeInfo {
	name, _ := os.Hostname()
	info := &agentv1.NodeInfo{Hostname: name, Platform: runtime.GOOS, Addresses: []string{}}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return info
	}
	seen := map[string]bool{}
	for _, addr := range addresses {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || !ip.IsGlobalUnicast() {
			continue
		}
		seen[ip.String()] = true
	}
	for a := range seen {
		info.Addresses = append(info.Addresses, a)
	}
	sort.Strings(info.Addresses)
	if len(info.Addresses) > 32 {
		info.Addresses = info.Addresses[:32]
	}
	return info
}
