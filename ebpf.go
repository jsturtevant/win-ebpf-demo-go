package main

// #cgo CFLAGS: -IeBPF-for-Windows.0.4.0/build/native/include -IeBPF-for-Windows.0.4.0/build/native/include/libbpf/include/ -w
// #cgo LDFLAGS: -L${SRCDIR}/eBPF-for-Windows.0.4.0/build/native/bin -lEbpfApi
// #include <stdlib.h>
// #include <stdint.h>
// #include "sal.h"
// #include "bpf/bpf.h"
// #include "bpf/libbpf.h"
// #include "ebpf_api.h"
// #include "linux/types.h"
// #include "ebpf/socket_headers.h"
import "C"
import (
	"unsafe"
)

func getProgramFD(programName string) C.int {
	// the name is the same as the function defined as attach point with SEC("cgroup/connect4")
	objName := C.CString(programName)
	fd := C.bpf_obj_get(objName)
	C.free(unsafe.Pointer(objName))
	return fd
}

func getbpfobject(file string) *C.struct_bpf_object {
	objName := C.CString(file)
	bpfObj := C.bpf_object__open(objName)
	C.free(unsafe.Pointer(objName))
	return bpfObj
}

func loadbfp(object *C.struct_bpf_object) int {
	return int(C.bpf_object__load(object))
}

func attachbfpProgram(prog *C.struct_bpf_program) *C.struct_bpf_link {
	return C.bpf_program__attach(prog)
}

func getProgram(obj *C.struct_bpf_object, name string) *C.struct_bpf_program {
	objName := C.CString(name)
	program := C.bpf_object__find_program_by_name(obj, objName)
	C.free(unsafe.Pointer(objName))
	return program
}

func getmap(object *C.struct_bpf_object, name string) *C.struct_bpf_map {
	objName := C.CString(name)
	redirectMap := C.bpf_object__find_map_by_name(object, objName)
	C.free(unsafe.Pointer(objName))
	return redirectMap
}

func getmapFD(object *C.struct_bpf_map) C.int {
	fd := C.bpf_map__fd(object)
	return fd
}

func getmapFDBybpfObject(object *C.struct_bpf_object, mapName string) C.int {
	objName := C.CString(mapName)
	fd := C.bpf_object__find_map_fd_by_name(object, objName)
	C.free(unsafe.Pointer(objName))
	return fd
}

func getMapName(object *C.struct_bpf_map) string {
	s := C.bpf_map__name(object)
	return C.GoString(s)
}

func updateMap(fd C.int, key unsafe.Pointer, value unsafe.Pointer, flags C.ulonglong) int {

	return int(C.bpf_map_update_elem(fd, key, value, flags))
}

func getMapElem(fd C.int, key unsafe.Pointer, value unsafe.Pointer) int {

	return int(C.bpf_map_lookup_elem(fd, key, value))
}
