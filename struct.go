package main

import (
	"encoding/binary"
	"net"
)

type ips struct {
	dstip   uint32
	dstport uint16
}

func newIP(ip net.IP) *ips {
	key := &ips{
		dstip:   ip2int(ip),
		dstport: 0, //todo figure out the port format
	}
	return key
}

// https://gist.github.com/ammario/649d4c0da650162efd404af23e25b86b
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
