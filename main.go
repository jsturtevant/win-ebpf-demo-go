package main

// #include "eBPF-for-Windows.0.4.0/build/native/include/ebpf_api.h"
import "C"
import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"syscall"
)

func main() {
	var ebpf = flag.String("ebpf", "cgroup_sock_addr.o", "ebpf program to install")
	flag.Parse()

	cmd := exec.Command("netsh", "ebpf", "add", "program", *ebpf)
	out, err := cmd.CombinedOutput()
	fmt.Printf("%q\n", string(out))
	if err != nil {
		log.Fatalf("unable to run command %v", err)
	}
	re := regexp.MustCompile(`\d+`)
	id := re.FindAllString(string(out), -1)
	fmt.Printf("id: %s\n", id)

	v := getProgramFD()
	fmt.Printf("program: %d\n", v)

	o := getbpfobject()
	fmt.Printf("object: %s\n", o)

	m := getmap(o)
	fmt.Printf("map: %s\n", m)

	mapFd := getmapFD(m)
	fmt.Printf("map id: %d\n", mapFd)

	mapfd2 := getmapFDBybpfObject(o)
	fmt.Printf("map id2: %d\n", mapfd2)

	name := getMapName(m)
	fmt.Printf("map name: %s\n", name)

	ip := newIP()
	mapupdate := updateMap(mapFd, &ip, &ip, 0)
	fmt.Printf("updatemap: %d", mapupdate)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("press ctrl+c to continue...")
	<-done

	cmd = exec.Command("netsh", "ebpf", "delete", "program", id[0])
	out, _ = cmd.CombinedOutput()
	fmt.Printf("%q", out)
}
