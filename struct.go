package main

type ips struct {
	dstip   uint32
	dstport uint16
	newip   uint32
	newport uint16
}

func newIP() *ips {
	//dest, _ := strconv.ParseUint("10.2.2.2", 10, 32)
	// dest_port, _ := strconv.ParseUint("80", 10, 16)
	// new_dest, _ := strconv.ParseUint("1.1.1.1", 10, 32)
	// new_dest_port, _ := strconv.ParseUint("80", 10, 16)
	key := &ips{
		dstip:   1,
		dstport: 0,
		newip:   0,
		newport: 0,
	}
	return key
}
