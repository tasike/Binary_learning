```
tasike@tasike-VM:~/Desktop$ file pwn20
pwn20: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=31ef1fb0ee2ff2932d1afbe4a4820c9939d488a4, not stripped
tasike@tasike-VM:~/Desktop$ checksec pwn20
[*] '/home/tasike/Desktop/pwn20'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

RELRO保护有三种状态：

1. No RELRO：在这种状态下，GOT和PLT都是可写的，意味着攻击者可以修改这些表中的指
   针，从而进行攻击。这是最弱的保护状态。
2. Partial RELRO：在这种状态下，GOT的开头部分被设置为只读（RO），而剩余部分仍然可
   写。这样可以防止一些简单的攻击，但仍存在一些漏洞。
3. Full RELRO：在这种状态下，GOT和PLT都被设置为只读（RO）。这样做可以防止对这些结构
   的修改，提供更强的保护。任何对这些表的修改都会导致程序异常终止。

----------------

接下来这步不知道是要干啥，也许是看libc的版本？反正这里我是跟着WP做的

```
tasike@tasike-VM:~/Desktop$ objdump -R pwn20

pwn20:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE 
0000000000600f18 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.2.5
0000000000600f20 R_X86_64_GLOB_DAT  __gmon_start__
0000000000600f40 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
0000000000600f48 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
0000000000600f50 R_X86_64_JUMP_SLOT  strtol@GLIBC_2.2.5


```

---------

查看表项地址

```
tasike@tasike-VM:~/Desktop$ readelf -S pwn20
There are 29 section headers, starting at offset 0x1878:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400200  00000200
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             000000000040021c  0000021c
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.bu[...] NOTE             000000000040023c  0000023c
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000400260  00000260
       000000000000001c  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           0000000000400280  00000280
       0000000000000090  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000400310  00000310
       000000000000004b  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000040035c  0000035c
       000000000000000c  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000400368  00000368
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000400388  00000388
       0000000000000030  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000004003b8  000003b8
       0000000000000048  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         0000000000400400  00000400
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         0000000000400420  00000420
       0000000000000040  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         0000000000400460  00000460
       0000000000000252  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         00000000004006b4  000006b4
       0000000000000009  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         00000000004006c0  000006c0
       000000000000053a  0000000000000000   A       0     0     8
  [16] .eh_frame_hdr     PROGBITS         0000000000400bfc  00000bfc
       000000000000003c  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000400c38  00000c38
       0000000000000100  0000000000000000   A       0     0     8
  [18] .init_array       INIT_ARRAY       0000000000600d38  00000d38
       0000000000000008  0000000000000008  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       0000000000600d40  00000d40
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .dynamic          DYNAMIC          0000000000600d48  00000d48
       00000000000001d0  0000000000000010  WA       6     0     8
  [21] .got              PROGBITS         0000000000600f18  00000f18
       0000000000000010  0000000000000008  WA       0     0     8
  [22] .got.plt          PROGBITS         0000000000600f28  00000f28
       0000000000000030  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000600f58  00000f58
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000600f68  00000f68
       0000000000000008  0000000000000000  WA       0     0     1
  [25] .comment          PROGBITS         0000000000000000  00000f68
       0000000000000029  0000000000000001  MS       0     0     1
  [26] .symtab           SYMTAB           0000000000000000  00000f98
       00000000000005e8  0000000000000018          27    43     8
  [27] .strtab           STRTAB           0000000000000000  00001580
       00000000000001f1  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00001771
       0000000000000103  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```

可以发现[21]和[22]就是.got和.got.plt，得知它们的地址分别为0x600f18和0x600f28，对应的Flags分别为WA和WA，因此都是可写的。

先测试一下.got：

```
tasike@tasike-VM:~/Desktop$ ./pwn20 0x600f18
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  
    * *************************************                           
    * Classify: CTFshow --- PWN --- 入门                              
    * Type  : Linux_Security_Mechanisms                               
    * Site  : https://ctf.show/                                       
    * Hint  : What is RELRO protection ?                              
    * *************************************                           
RELRO: 52454c52

```

从而.got确实可写，

再测试一下.got.plt:
```
tasike@tasike-VM:~/Desktop$ ./pwn20 0x600f28
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  
    * *************************************                           
    * Classify: CTFshow --- PWN --- 入门                              
    * Type  : Linux_Security_Mechanisms                               
    * Site  : https://ctf.show/                                       
    * Hint  : What is RELRO protection ?                              
    * *************************************                           
RELRO: 52454c52
tasike@tasike-VM:~/Desktop$ 

```

从而两个都可写。

