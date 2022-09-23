nuget install eBPF-for-Windows
clang -I .\eBPF-for-Windows.0.4.0\build\native\include\ -target bpf -Werror -g -O2 -c ebpf/cgroup_sock_addr.c -o cgroup_sock_addr.o
netsh ebpf show verification .\cgroup_sock_addr.o type=cgroup/connect4
