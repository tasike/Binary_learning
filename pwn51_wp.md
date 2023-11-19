```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn51
```

```
tasike@tasike-VM:~/Desktop$ file pwn51
pwn51: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=948891884c9b0d405b050ac809c06cbb25e49774, stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn51
[*] '/home/tasike/Desktop/pwn51'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`32bit`，堆栈不可执行

`ida`查看

```c
int __cdecl main(int a1)
{
  sub_80492E6(&a1);
  sub_8049343();
  alarm(0x1Eu);
  sub_8049059();
  return 0;
}
```

发现符号表被扣了，那只能一个一个跟进了：
跟进`sub_80492E6`

```c
int sub_80492E6()
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  return setvbuf(stderr, 0, 2, 0);
}
```

很显然是`init`函数，为了便于分析，鼠标点击`sub_80492E6`，再按`N`，宠儿个人