package main

// #cgo CFLAGS: -IeBPF-for-Windows.0.4.0/build/native/include -IeBPF-for-Windows.0.4.0/build/native/include/libbpf/include/ -w
// #cgo LDFLAGS: -L${SRCDIR}/eBPF-for-Windows.0.4.0/build/native/bin -lEbpfApi
// #include <stdlib.h>
// #include "sal.h"
// #include "bpf/bpf.h"
// #include "bpf/libbpf.h"
// #include "linux/types.h"
// #include "ebpf/socket_headers.h"
import "C"
import (
	"unsafe"
)

func getProgramFD() C.int {
	// the name is the same as the function defined as attach point with SEC("cgroup/connect4")
	objName := C.CString("redirect")
	fd := C.bpf_obj_get(objName)
	C.free(unsafe.Pointer(objName))
	return fd
}

func getbpfobject() *C.struct_bpf_object {
	objName := C.CString("cgroup_sock_addr.o")
	bpfObj := C.bpf_object__open(objName)
	C.free(unsafe.Pointer(objName))
	return bpfObj
}

func getmap(object *C.struct_bpf_object) *C.struct_bpf_map {
	objName := C.CString("egress_connection_policy_map")
	redirectMap := C.bpf_object__find_map_by_name(object, objName)
	C.free(unsafe.Pointer(objName))
	return redirectMap
}

func getmapFD(object *C.struct_bpf_map) C.int {
	fd := C.bpf_map__fd(object)
	return fd
}

func getmapFDBybpfObject(object *C.struct_bpf_object) C.int {
	objName := C.CString("egress_connection_policy_map")
	fd := C.bpf_object__find_map_fd_by_name(object, objName)
	C.free(unsafe.Pointer(objName))
	return fd
}

func getMapName(object *C.struct_bpf_map) string {
	s := C.bpf_map__name(object)
	return C.GoString(s)
}

func updateMap(fd C.int, key *C.struct_connection, value *C.struct_connection, flags C.ulonglong) int {

	return int(C.bpf_map_update_elem(fd, unsafe.Pointer(key), unsafe.Pointer(value), flags))
}
