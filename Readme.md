# ebpf for windows example

Demo using ebpf from golang to redirect traffic.  This is just a proof of concept.

Requires:

- VM that can deploy [Windows Drivers](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/vm-setup.md)
- [eBPF for Windows](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/InstallEbpf.md#method-1-install-a-release) installed  
- [Clang 64-bit version 11.0.1](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/LLVM-11.0.1-win64.exe). Note: clang versions 12 and higher are NOT yet supported.  Must be on path.
- [nuget.exe](https://www.nuget.org/downloads) installed 

## generate ebpf program

```powershell
#from admin prompt
./gen-ebpf.ps1
```

## run the program

```
go run .
```

## tracing ebpf program

Needs [WDK installed](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

```powershell
#from admin prompt
./trace.ps1
```