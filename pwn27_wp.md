同pwn26

根据题目所述，还是关于修改ASLR参数设置来获取flag

----------

```
tasike@tasike-VM:~/Desktop$ file pwn27
pwn27: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=bc92a5385cfc5bdc2064c416165fa7b95d95b4e0, not stripped

tasike@tasike-VM:~/Desktop$ checksec pwn27
[*] '/home/tasike/Desktop/pwn27'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

64位，部分开启RELRO保护，堆栈不可执行

----

用IDA查看：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *ptr; // [rsp+0h] [rbp-10h]

  ptr = malloc(4uLL);
  dlopen("./libc-2.27.so", 258);
  puts(s);
  puts(asc_4008D0);
  puts(asc_400950);
  puts(asc_4009E0);
  puts(asc_400A70);
  puts(asc_400AF8);
  puts(asc_400B90);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Linux_Security_Mechanisms                               ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : Please confirm your ASLR level first !                  ");
  puts("    * *************************************                           ");
  puts("Here is your ASLR level:");
  system("cat /proc/sys/kernel/randomize_va_space");
  puts("If the result is 0 or 1, then you get the correct flag!");
  puts("If not,you will get a fake flag!");
  printf("flag is :ctfshow{%p", main);
  printf("_%p", system);
  printf("_%p", ptr);
  puts("}");
  free(ptr);
  return 0;
}
```

同样只需覆写/proc/sys/kernel/randomize_va_space为0或者1即可。

由于上一题刚刚覆写完，所以该文件本身就是0了

```
tasike@tasike-VM:~/Desktop$ cat /proc/sys/kernel/randomize_va_space
0

tasike@tasike-VM:~/Desktop$ ./pwn27
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
If the result is 0 or 1, then you get the correct flag!
If not,you will get a fake flag!
flag is :ctfshow{0x400687_0x400560_0x6032a0}
```

