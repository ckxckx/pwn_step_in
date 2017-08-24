#coding:utf-8
'''
command:
get 1  ----get_file()
            ---输入filename
            ---回显带fmt的字符串content
put 2  ----get_input() x2
            ---filename
            ---filecontent
dir 3  ----show_dir()
'''
from pwn import *
p=process("./pwn3")
context.log_level='debug'
p.recvuntil("Name (ftp.hacker.server:Rainism):")
p.sendline("rxraclhm")
# p.sendline("r")
print p.recvuntil("ftp>")
p.sendline("put")
print p.recvuntil("upload:")


#printf 0804889E
#get   080487F6
gdb.attach(p,'''
B *0x08048777
B *0x080487F6
B *0x0804889E
''')
raw_input("sending putfile.... ")
p.sendline("AAAA")
print p.recvuntil("content:")
p.sendline("ABAB")
print p.recvuntil("ftp>")
p.sendline("get")
print p.recvuntil("get:")
p.sendline("AAAA")
print p.recvuntil("ftp>")
# def putfile(filenme,content):
#     p.sendline("")
