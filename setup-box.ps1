# must be run as Admin
cp "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.33.31629\include\sal.h" .

# these services must be runnig
net start netebpfext
net start ebpfcore
net start ebpfsvc