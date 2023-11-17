同pwn26

通过覆写ASLR为我们需要的值来获取flag

----------

```
tasike@tasike-VM:~/Desktop$ file pwn28
pwn28: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=5fef88bb9cee29bfa6a577c974c969b9b0624d3c, not stripped
tasike@tasike-VM:~/Desktop$ checksec pwn28
[*] '/home/tasike/Desktop/pwn28'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

64bit，部分开启RELRO，堆栈不可执行

----------

IDA：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *ptr; // [rsp+0h] [rbp-10h]

  ptr = malloc(4uLL);
  dlopen("./libc-2.27.so", 258);
  puts(s);
  puts(asc_4008A0);
  puts(asc_400920);
  puts(asc_4009B0);
  puts(asc_400A40);
  puts(asc_400AC8);
  puts(asc_400B60);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Linux_Security_Mechanisms                               ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : Please confirm your ASLR level first !                  ");
  puts("    * *************************************                           ");
  puts("Here is your ASLR level:");
  system("cat /proc/sys/kernel/randomize_va_space");
  printf("flag is :ctfshow{%p", main);
  printf("_%p", system);
  puts("}");
  free(ptr);
  return 0;
}
```

未说明ASLR的全局配置/proc/sys/kernel/randomize_va_space文件的值，因此要都试一遍

```
tasike@tasike-VM:~/Desktop$ sudo su

root@tasike-VM:/home/tasike/Desktop# echo 0 > /proc/sys/kernel/randomize_va_space
root@tasike-VM:/home/tasike/Desktop# ./pwn28
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
flag is :ctfshow{0x400687_0x400560}


root@tasike-VM:/home/tasike/Desktop# echo 1 > /proc/sys/kernel/randomize_va_space
root@tasike-VM:/home/tasike/Desktop# ./pwn28
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
1
flag is :ctfshow{0x400687_0x400560}


root@tasike-VM:/home/tasike/Desktop# echo 2 > /proc/sys/kernel/randomize_va_space
root@tasike-VM:/home/tasike/Desktop# ./pwn28
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
2
flag is :ctfshow{0x400687_0x400560}

```

显然无论ASLR被设置为0或者1或者2均不改变答案。