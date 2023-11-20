```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn56
```

```
tasike@tasike-VM:~/Desktop$ file pwn56
pwn56: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn56
[*] '/home/tasike/Desktop/pwn56'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

`32bit`，未开启任何保护

`ida`查看

```c
void __noreturn start()
{
  int v0; // eax
  char v1[10]; // [esp-Ch] [ebp-Ch] BYREF
  __int16 v2; // [esp-2h] [ebp-2h]

  v2 = 0;
  strcpy(v1, "/bin///sh");
  v0 = sys_execve(v1, 0, 0);
}
```

就一个函数，而且貌似直接就获得最高权限了？

于是在本地试一下

```
tasike@tasike-VM:~/Desktop$ ./pwn56
$ ls
CGfsb				     attack_format_level3.py	 attack_shellcode_level3.py	   format_level3  pwn56		    tasike.c
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

还真是获取最高权限了，那这题都不需要脑子（笑哭.jpg）

```
tasike@tasike-VM:~/Desktop$ nc pwn.challenge.ctf.show 28219

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
ctfshow{6fa139f7-bad3-46d2-9604-1a2213a47794}
```

