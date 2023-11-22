```
tasike@tasike-VM:~/Desktop$ file pwn22
pwn22: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8ce7ae4c828948048cdb392352234a1cab26b33e, not stripped
tasike@tasike-VM:~/Desktop$ checksec pwn22
[*] '/home/tasike/Desktop/pwn22'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

这次开启了Full RELRO，也就是GOT和PLT都是只读的，不过仍然还是要查看一下。

-------

这步是传统艺能的查看，不知道有什么用(我的理解是看libc的版本，如果不对的话，那就不对吧，反正多一行无用的命令也无妨)

```
tasike@tasike-VM:~/Desktop$ objdump -R pwn22

pwn22:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE 
0000000000600ff0 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.2.5
0000000000600ff8 R_X86_64_GLOB_DAT  __gmon_start__
0000000000600fd8 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
0000000000600fe0 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
0000000000600fe8 R_X86_64_JUMP_SLOT  strtol@GLIBC_2.2.5


```

----------

查看表项地址：

```
tasike@tasike-VM:~/Desktop$ readelf -S pwn22
There are 28 section headers, starting at offset 0x1900:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.bu[...] NOTE             0000000000400274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000400298  00000298
       000000000000001c  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000004002b8  000002b8
       0000000000000090  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000400348  00000348
       000000000000004b  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           0000000000400394  00000394
       000000000000000c  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          00000000004003a0  000003a0
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             00000000004003c0  000003c0
       0000000000000030  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000004003f0  000003f0
       0000000000000048  0000000000000018  AI       5    21     8
  [11] .init             PROGBITS         0000000000400438  00000438
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         0000000000400450  00000450
       0000000000000040  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         0000000000400490  00000490
       0000000000000252  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         00000000004006e4  000006e4
       0000000000000009  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         00000000004006f0  000006f0
       000000000000053a  0000000000000000   A       0     0     8
  [16] .eh_frame_hdr     PROGBITS         0000000000400c2c  00000c2c
       000000000000003c  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000400c68  00000c68
       0000000000000100  0000000000000000   A       0     0     8
  [18] .init_array       INIT_ARRAY       0000000000600dc0  00000dc0
       0000000000000008  0000000000000008  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       0000000000600dc8  00000dc8
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .dynamic          DYNAMIC          0000000000600dd0  00000dd0
       00000000000001f0  0000000000000010  WA       6     0     8
  [21] .got              PROGBITS         0000000000600fc0  00000fc0
       0000000000000040  0000000000000008  WA       0     0     8
  [22] .data             PROGBITS         0000000000601000  00001000
       0000000000000010  0000000000000000  WA       0     0     8
  [23] .bss              NOBITS           0000000000601010  00001010
       0000000000000008  0000000000000000  WA       0     0     1
  [24] .comment          PROGBITS         0000000000000000  00001010
       0000000000000029  0000000000000001  MS       0     0     1
  [25] .symtab           SYMTAB           0000000000000000  00001040
       00000000000005d0  0000000000000018          26    42     8
  [26] .strtab           STRTAB           0000000000000000  00001610
       00000000000001f1  0000000000000000           0     0     1
  [27] .shstrtab         STRTAB           0000000000000000  00001801
       00000000000000fa  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

```

发现只有.got，地址为0x600fc0，但是它这里写个WA是糊弄谁呢？（==越发觉得这逼命令估计只能信它的地址了，它这个权限是真有些。。。。==）

还是一样，仔细查看程序头：
```
tasike@tasike-VM:~/Desktop$ readelf -l pwn22

Elf file type is EXEC (Executable file)
Entry point 0x400490
There are 9 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x00000000000001f8 0x00000000000001f8  R      0x8
  INTERP         0x0000000000000238 0x0000000000400238 0x0000000000400238
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x0000000000000d68 0x0000000000000d68  R E    0x200000
  LOAD           0x0000000000000dc0 0x0000000000600dc0 0x0000000000600dc0
                 0x0000000000000250 0x0000000000000258  RW     0x200000
  DYNAMIC        0x0000000000000dd0 0x0000000000600dd0 0x0000000000600dd0
                 0x00000000000001f0 0x00000000000001f0  RW     0x8
  NOTE           0x0000000000000254 0x0000000000400254 0x0000000000400254
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x0000000000000c2c 0x0000000000400c2c 0x0000000000400c2c
                 0x000000000000003c 0x000000000000003c  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000000dc0 0x0000000000600dc0 0x0000000000600dc0
                 0x0000000000000240 0x0000000000000240  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .init_array .fini_array .dynamic .got .data .bss 
   04     .dynamic 
   05     .note.ABI-tag .note.gnu.build-id 
   06     .eh_frame_hdr 
   07     
   08     .init_array .fini_array .dynamic .got 

```

基于上一题的经验，很显然又是这个GNU_RELRO的程序头在搞鬼，先不管三七二之一把只读区间搞出来：[0x600dc0,0x601000)，显然.got(0x600fc0)也在里面，因此它只读。

测试一下：
```
tasike@tasike-VM:~/Desktop$ ./pwn22 0x600fc0
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
Segmentation fault (core dumped)

```

确实不可写。