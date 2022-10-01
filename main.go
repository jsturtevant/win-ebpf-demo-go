package main

// #include "eBPF-for-Windows.0.4.0/build/native/include/ebpf_api.h"
import "C"
import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

func main() {
	var ebpf = flag.String("ebpf", "cgroup_sock_addr.o", "ebpf program to install")
	var addressToBlock = flag.String("addr", "18.207.88.57", "address to block")
	flag.Parse()

	o := getbpfobject(*ebpf)
	fmt.Printf("object: %s\n", o)

	// we don't pin it so it doesn't stay loaded
	s := loadbfp(o)
	fmt.Printf("loaded: %d\n", s)

	// the name is the same as the function defined as attach point with SEC("cgroup/connect4")
	p := getProgram(o, "redirect")
	fmt.Printf("program: %v\n", p)

	l := attachbfpProgram(p)
	fmt.Printf("link: %v\n", l)

	polMap := getmap(o, "egress_connection_policy_map")
	fmt.Printf("map: %s\n", polMap)

	mapFd := getmapFD(polMap)
	fmt.Printf("map id: %d\n", mapFd)

	mapfd2 := getmapFDBybpfObject(o, "egress_connection_policy_map")
	fmt.Printf("map id2: %d\n", mapfd2)

	name := getMapName(polMap)
	fmt.Printf("map name: %s\n", name)

	ipToBlock := net.ParseIP(*addressToBlock)
	ip := newIP(ipToBlock)
	fmt.Printf("ip in unsigned int: %d\n", ip.dstip)
	ipp := unsafe.Pointer(ip)
	mapupdate := updateMap(mapFd, ipp, ipp, 0)
	fmt.Printf("updatemap with ip %s result: %d\n", ipToBlock.String(), mapupdate)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("press ctrl+c to continue...")
	<-done

	v2 := ips{}
	r := getMapElem(mapFd, unsafe.Pointer(ip), unsafe.Pointer(&v2))

	ipstored := int2ip(v2.dstip)
	fmt.Printf("return value: %d. getmap el: %v\n", r, v2)
	fmt.Printf("return ip is: %s:%v\n", ipstored.String(), v2.dstport)

	//TODO clean everything up (link)
}
