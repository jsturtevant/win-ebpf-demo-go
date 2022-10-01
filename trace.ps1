# must have wdk installed
# get other trace file guids from https://github.com/microsoft/ebpf-for-windows/tree/main/scripts
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x86\tracelog.exe" -stop connect4

& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x86\tracelog.exe" -start connect4 -guid ebpf-printk.guid -rt

write-host "starting trace, stop with 'tracelog -stop connect4'"
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x86\tracefmt.exe" -rt connect4 -displayonly -jsonMeta 0

