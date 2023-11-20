```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn57
```

```
tasike@tasike-VM:~/Desktop$ file pwn57
pwn57: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn57
[*] '/home/tasike/Desktop/pwn57'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
```

`64bit`，啥保护都没开，甚至还是`静态链接`

`ida`查看

```c
void __noreturn start()
{
  __asm { syscall; LINUX - }
}
```

绝绝子，就这么一个函数

查一下：

```
这段代码是一个名为start的函数，它使用汇编语言编写。该函数的作用是执行一个系统调用（syscall），并返回到Linux内核空间。

在函数内部，使用了__asm关键字来指定汇编代码块。syscall指令用于执行系统调用，而LINUX -表示跳转到Linux内核空间。
```

于是想着本地试着运行一下：
```
tasike@tasike-VM:~/Desktop$ ./pwn57
$ ls
CGfsb				     attack_format_level3.py	 attack_shellcode_level3.py	   format_level3  pwn57		    tasike.c
CGfsb_exp.py			     attack_little_canary.py	 attack_uninitialized_key.py	   heap_Easy_Uaf  pwn6		    test
LibcSearcher.py			     attack_name4.py		 attack_uninitialized_key_plus.py  level0_exp.py  pwndbg	    test.c
PIE_enabled			     attack_play.py		 attack_woof.py			   level2_exp.py  rePWNse	    test.py
VMwareTools-10.3.25-20206839.tar.gz  attack_rePWNse.py		 checksec.sh			   little_canary  ret2libc	    test_int_overflow.c
__pycache__			     attack_ret2libc.py		 exp.py				   name4	  ret2syscall	    uninitialized_key
attack.py			     attack_ret2syscall.py	 f1ag				   play		  ret2text_32	    uninitialized_key_plus
attack52.py			     attack_ret2text_32.py	 fakeflag-backend		   pwn25	  ret2text_64	    vmware-tools-distrib
attack53.py			     attack_ret2text_64.py	 fd.c				   pwn30	  shellcode_level0  woof
attack_PIE_enabled.py		     attack_shellcode_level0.py  fork.c				   pwn51	  shellcode_level1
attack_format_level0.py		     attack_shellcode_level1.py  format_level0			   pwn52	  shellcode_level2
attack_format_level1.py		     attack_shellcode_level2.py  format_level1			   pwn53	  shellcode_level3
```

那么很显然了，这题不需要脑子

```
tasike@tasike-VM:~/Desktop$ nc pwn.challenge.ctf.show 28179
ls
bin
boot
ctfshow_flag
dev
etc
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
start.sh
sys
tmp
usr
var
cat ctfshow_flag
ctfshow{e5d7a8f8-a9fb-4028-8ff0-9e496c06b49d}
```

