首先题目说设置好ALSR保护即可获得flag

> ASLR（Address Space Layout Randomization）是一种==操作系统级别的安全保护机制==，旨在增加
> 软件系统的安全性。它通过随机化程序在内存中的布局，使得攻击者难以准确地确定关键代码和数据的
> 位置，从而增加了利用软件漏洞进行攻击的难度。
>
> 
>
> 开启不同等级会有不同的效果：
>
> 1. 内存布局随机化： ASLR的主要目标是随机化程序的内存布局。在传统的内存布局中，不同的
>    库和模块通常会在固定的内存位置上加载，攻击者可以利用这种可预测性来定位和利用漏洞。
>    ASLR通过随机化这些模块的加载地址，使得攻击者无法准确地确定内存中的关键数据结构和
>    代码的位置。
> 2.  地址空间范围的随机化： ASLR还会随机化进程的地址空间范围。在传统的地址空间中，栈、
>    堆、代码段和数据段通常会被分配到固定的地址范围中。ASLR会随机选择地址空间的起始位
>    置和大小，从而使得这些重要的内存区域在每次运行时都有不同的位置。
> 3.  随机偏移量： ASLR会引入随机偏移量，将程序和模块在内存中的相对位置随机化。这意味着
>    每个模块的实际地址是相对于一个随机基址偏移的，而不是绝对地址。攻击者需要在运行时发
>    现这些偏移量，才能准确地定位和利用漏洞。
> 4.  堆和栈随机化： ASLR也会对堆和栈进行随机化。堆随机化会在每次分配内存时选择不同的起
>    始地址，使得攻击者无法准确地预测堆上对象的位置。栈随机化会随机选择栈帧的起始位置，
>    使得攻击者无法轻易地覆盖返回地址或控制程序流程。
>
>  
>
> 在Linux中，ALSR的==全局配置/proc/sys/kernel/randomize_va_space==有三种情况：
>
> - 0表示关闭ALSR
> - 1表示部分开启（将mmap的基址、stack和vdso页面随机化）
> - 2表示完全开启
>
> 下方的表格中(executable表示进程随机化，plt表示plt地址随机化，heap表示堆随机化，stack表示栈帧随机化，最后一个是库加载时的随机化)
>
> | ALSR  | Executable | PLT  | Heap | Stack | Shared libraries |
> | :---: | :--------: | :--: | :--: | :---: | :--------------: |
> |   0   |     ×      |  ×   |  ×   |   ×   |        ×         |
> |   1   |     ×      |  ×   |  ×   |   √   |        √         |
> |   2   |     ×      |  ×   |  √   |   √   |        √         |
> | 2+PIE |     √      |  √   |  √   |   √   |        √         |
>
> 



-----------

```
tasike@tasike-VM:~/Desktop$ file pwn26
pwn26: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7ae927cf210bd3cc4928a3978ecefd5c5ba4820b, not stripped
tasike@tasike-VM:~/Desktop$ checksec pwn26
[*] '/home/tasike/Desktop/pwn26'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

64位，部分开启RELRO保护，堆栈不可执行

----------

用IDA查看：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *ptr; // [rsp+0h] [rbp-10h]
  void *v5; // [rsp+8h] [rbp-8h]

  ptr = malloc(4uLL);
  v5 = dlopen("/lib/x86_64-linux-gnu/libc.so.6", 258);
  puts(s);
  puts(asc_4008F0);
  puts(asc_400970);
  puts(asc_400A00);
  puts(asc_400A90);
  puts(asc_400B18);
  puts(asc_400BB0);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Linux_Security_Mechanisms                               ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : Please confirm your ASLR level first !                  ");
  puts("    * *************************************                           ");
  puts("Here is your ASLR level:");
  system("cat /proc/sys/kernel/randomize_va_space");
  puts("If the result is 0, then you get the correct flag!");
  puts("If not,you will get a fake flag!");
  printf("flag is :ctfshow{%p", main);
  printf("_%p", system);
  printf("_%p", ptr);
  printf("_%p", v5);
  puts("}");
  free(ptr);
  return 0;
}
```

[Linux 中 dlopen、dlsym、dlclose、dlerror函数-CSDN博客](https://blog.csdn.net/no_compare_no_harm/article/details/89555366?ops_request_misc=%7B%22request%5Fid%22%3A%22169908494016800182754388%22%2C%22scm%22%3A%2220140713.130102334.pc%5Fall.%22%7D&request_id=169908494016800182754388&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-1-89555366-null-null.142^v96^pc_search_result_base9&utm_term=Linux中的dlopen函数&spm=1018.2226.3001.4187)

不过仍然没查到258的参数到底指的是哪个？（笑哭.jpg）

不过代码好理解，它的意思就是说如果22行执行之后是0那么就可以得到正确的flag。

这是自然不过的事情，因为如果22行执行后是0，说明ASLR完全关闭（上文已经提过，/proc/sys/kernel/randomize_va_space是ASLR的全局配置文件），因此上文表格中的所有的随机化关闭，下面的flag实际上是由main的地址，system的四肢，ptr动态申请的堆地址和v5的栈地址组成的，因此就是固定的值而非一直随机化的变化值。



为了让22行执行后是0来得到flag，首先我们需要把/proc/sys/kernel/randomize_va_space覆写为0，再运行程序从而得到flag

```
tasike@tasike-VM:~/Desktop$ echo 0>/proc/sys/kernel/randomize_va_space
bash: /proc/sys/kernel/randomize_va_space: Permission denied

tasike@tasike-VM:~/Desktop$ sudo su 
[sudo] password for tasike: 

root@tasike-VM:/home/tasike/Desktop# echo 0 > /proc/sys/kernel/randomize_va_space
root@tasike-VM:/home/tasike/Desktop# ./pwn26
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
    * Hint  : Please confirm your ASLR level first !                  
    * *************************************                           
Here is your ASLR level:
0
If the result is 0, then you get the correct flag!
If not,you will get a fake flag!
flag is :ctfshow{0x400687_0x400560_0x6032a0_0x7ffff7fbb680}

```

