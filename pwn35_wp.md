> 常规查看位数和保护：
>
> ```
> tasike@tasike-VM:~/Desktop$ file pwn35
> pwn35: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4bc7dc523aa0fa7b67257abf83dba476524f4cd1, not stripped
> tasike@tasike-VM:~/Desktop$ checksec pwn35
> [*] '/home/tasike/Desktop/pwn35'
>     Arch:     i386-32-little
>     RELRO:    Partial RELRO
>     Stack:    No canary found
>     NX:       NX enabled
>     PIE:      No PIE (0x8048000)
> ```
>
> 由上可知：32位，动态链接，部分开启RELRO，开启堆栈不可执行
>
> 放入ida32中查看反编译的源码：
> ```
> int __cdecl main(int argc, const char **argv, const char **envp)
> {
>   FILE *stream; // [esp+0h] [ebp-1Ch]
> 
>   stream = fopen("/ctfshow_flag", "r");
>   if ( !stream )
>   {
>     puts("/ctfshow_flag: No such file or directory.");
>     exit(0);
>   }
>   fgets(flag, 64, stream);
>   signal(11, (__sighandler_t)sigsegv_handler);
>   puts(asc_8048910);
>   puts(asc_8048984);
>   puts(asc_8048A00);
>   puts(asc_8048A8C);
>   puts(asc_8048B1C);
>   puts(asc_8048BA0);
>   puts(asc_8048C34);
>   puts("    * *************************************                           ");
>   puts(aClassifyCtfsho);
>   puts("    * Type  : Stack_Overflow                                          ");
>   puts("    * Site  : https://ctf.show/                                       ");
>   puts("    * Hint  : See what the program does!                              ");
>   puts("    * *************************************                           ");
>   puts("Where is flag?\n");
>   if ( argc <= 1 )
>   {
>     puts("Try again!");
>   }
>   else
>   {
>     ctfshow((char *)argv[1]);
>     printf("QaQ!FLAG IS NOT HERE! Here is your input : %s", argv[1]);
>   }
>   return 0;
> }
> ```
>
> 显然，不能直接放在本地打，因为本地并没有ctfshow_flag文件，因此运行的时候会执行第6行的if语句然后退出。
>
> 查询fgets函数：
> [fgets函数及其用法，C语言fgets函数详解 (biancheng.net)](https://c.biancheng.net/view/235.html)
>
> **因此11行：从ctfshow_flag中读取64个字符写入flag所指向的内存，返回flag指针**
>
> 查询signal函数：
>
> 
>
> 查询argc和argv:
>
> [c语言中argc和argv的作用及用法-CSDN博客](https://blog.csdn.net/zhaozhiyuan111/article/details/104050729)
>
> 连接靶场的时候相当于在远程运行了可执行程序，那么argc=1，argv[0] = nc ip(要连接的远程靶场的ip) port(要连接的远程靶场的端口)。
>
> **因此要使得argc > 1，即要执行else里的ctfshow函数，就要在nc的后面继续写参数(显然从上述的查询中得知参数可以是随便的东西，反正都被当作参数)**
>
> 

