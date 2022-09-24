package main

// struct connection
// {
//     unsigned int dst_ip;
//     unsigned short dst_port;
//     unsigned int new_dst_ip;
//     unsigned short new_dst_port;
// };
import "C"

func newIP() C.struct_connection {
	//dest, _ := strconv.ParseUint("10.2.2.2", 10, 32)
	// dest_port, _ := strconv.ParseUint("80", 10, 16)
	// new_dest, _ := strconv.ParseUint("1.1.1.1", 10, 32)
	// new_dest_port, _ := strconv.ParseUint("80", 10, 16)
	key := C.struct_connection{
		dst_ip:       0,
		dst_port:     0,
		new_dst_ip:   0,
		new_dst_port: 0,
	}
	return key
}
