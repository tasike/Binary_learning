```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn58
```

```
tasike@tasike-VM:~/Desktop$ file pwn58
pwn58: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=08e1f028d9d071183aaaab2db16603c8dd3d6807, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn58
[*] '/home/tasike/Desktop/pwn58'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

`32bit`，啥保护都没开，而且具有可读可写可执行段

`ida`查看

```c
```

