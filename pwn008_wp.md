> 显然下载的asm文件打开后，不能得知msg的地址，因此考虑下载前面那个elf可执行文件
>
> 下载后复制到linux中，查看文件类型，以便用ida打开
>
> ```
> tasike@tasike-VM:~/Desktop$ file pwn8
> pwn8: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped
> ```
>
> 该elf可执行文件为32位，静态链接(statically linked)，那么使用ida32打开，按空格切换到有详细地址的反汇编界面，找到对应的语句：
>
> ```assembly
> .text:08048094 8B 0D E8 90 04 08             mov     ecx, dword_80490E8
> ```
>
> 跟进dword_80490E8
>
> ```assembly
> .data:080490E8 57 65 6C 63                   dword_80490E8 dd 636C6557h              ; DATA XREF: LOAD:0804805C↑o
> ```
>
> 因此地址为0x80490E8,
>
> ctfshow{0x80490E8}

