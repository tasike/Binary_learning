> 和 上一题一样的asm文件和ida反汇编文件，对标所求代码段：
> ```assembly
> .text:080480A1 B9 E8 90 04 08                mov     ecx, offset dword_80490E8
> .text:080480A6 83 C1 04                      add     ecx, 4
> .text:080480A9 8B 01                         mov     eax, [ecx]
> ```
>
> 也就是把dword_80490E8的地址值赋给ecx，然后ecx加4，然后把ecx所指向的数据(或者说ecx的引用值)赋值给eax
>
> 首先跟进dword_80490E8:
> ```assembly
> .data:080490E8 57 65 6C 63                   dword_80490E8 dd 636C6557h              ; DATA XREF: LOAD:0804805C↑o
> ```
>
> 那么加4之后，地址应为080490EC，往下翻：
>
> ```assembly
> .data:080490EC 6F 6D 65 5F 74 6F 5F 43 54 46+aOmeToCtfshowPw db 'ome_to_CTFshow_PWN',0
> ```
>
> 因此该地址下的数据就是'ome_to_CTFshow_PWN'
>
> ctfshow{ome_to_CTFshow_PWN}