package main

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
	fmt.Printf("id: %s", id)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("press ctrl+c to continue...")
	<-done

	cmd = exec.Command("netsh", "ebpf", "delete", "program", id[0])
	out, _ = cmd.CombinedOutput()
	fmt.Printf("%q", out)
}
