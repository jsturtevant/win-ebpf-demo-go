# ebpf for windows example

Demo using ebpf from golang to redirect traffic.  This is just a proof of concept.

## generate ebpf program

```powershell
#from admin prompt
./gen-ebpf.ps1
```

## run the program

```
go run .
```

## tracing

Needs WDK installed

```powershell
#from admin prompt
./trace.ps1
```