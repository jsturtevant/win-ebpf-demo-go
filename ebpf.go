package main

// #cgo CFLAGS: -IeBPF-for-Windows.0.4.0/build/native/include -IeBPF-for-Windows.0.4.0/build/native/include/libbpf/include/ -w
// #cgo LDFLAGS: -L${SRCDIR}/eBPF-for-Windows.0.4.0/build/native/bin -lEbpfApi
// #include <stdlib.h>
// #include "sal.h"
// #include "bpf/bpf.h"
// #include "libbpf/src/bpf.h"
// #include "linux/types.h"
// #include "linux/bpf.h"
import "C"

func getProgram() int {
	// the name is the same as the function defined as attach point with SEC("cgroup/connect4")
	return int(C.bpf_obj_get(C.CString("redirect")))
}
