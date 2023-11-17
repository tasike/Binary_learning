pwn26的基础上加上了PIE

--------

```
tasike@tasike-VM:~/Desktop$ file pwn29
pwn29: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=17f672fe6c194336238bda5dc66c1a7a5ddf4bee, not stripped
tasike@tasike-VM:~/Desktop$ checksec pwn29
[*] '/home/tasike/Desktop/pwn29'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

64bit，全部开启RELRO保护，开启Canary保护，堆栈不可执行，开启PIE地址空间分布随机化。

------

IDA：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[4]; // [rsp+4h] [rbp-1Ch] BYREF
  void *ptr; // [rsp+8h] [rbp-18h]
  void *v6; // [rsp+10h] [rbp-10h]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  ptr = malloc(4uLL);
  v6 = dlopen("./libc-2.27.so", 258);
  puts(s);
  puts(asc_B10);
  puts(asc_B90);
  puts(asc_C20);
  puts(asc_CB0);
  puts(asc_D38);
  puts(asc_DD0);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Linux_Security_Mechanisms                               ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : Please confirm your ASLR level first !                  ");
  puts("    * *************************************                           ");
  system("echo 2 > /proc/sys/kernel/randomize_va_space");
  puts("Here is your ASLR level:");
  system("cat /proc/sys/kernel/randomize_va_space");
  puts("Let's take a look at protection:");
  system("checksec pwn");
  printf("executable: %p\n", main);
  printf("system@plt: %p\n", &system);
  printf("heap: %p\n", ptr);
  printf("stack: %p\n", v4);
  puts("As you can see, the protection has been fully turned on and the address has been completely randomized!");
  puts("Here is your flag:");
  puts("ctfshow{Address_Space_Layout_Randomization&&Position-Independent_Executable_1s_C0000000000l!}");
  free(ptr);
  return 0;
}
```

24行：将ASLR的全局配置文件/proc/sys/kernel/randomize_va_space覆写为2，也就是完全开启ASLR。

28行：查看pwn的保护，很显然，这题没有在线靶场，因此这个拖进来的pwn29文件要重命名为pwn。

但是看到35行在发现，这题只要运行就会得到flag。（笑哭.jpg）

------------

为了不辜负它白出这道题，就运行两遍，看看那些不同的地址：
```
tasike@tasike-VM:~/Desktop$ ./pwn
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
sh: 1: cannot create /proc/sys/kernel/randomize_va_space: Permission denied
Here is your ASLR level:
2
Let's take a look at protection:
[*] '/home/tasike/Desktop/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
executable: 0x5650c4a0083a
system@plt: 0x7f46c1050d70
heap: 0x5650c67b22a0
stack: 0x7ffc8a4a7254
As you can see, the protection has been fully turned on and the address has been completely randomized!
Here is your flag:
ctfshow{Address_Space_Layout_Randomization&&Position-Independent_Executable_1s_C0000000000l!}


tasike@tasike-VM:~/Desktop$ ./pwn
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
sh: 1: cannot create /proc/sys/kernel/randomize_va_space: Permission denied
Here is your ASLR level:
2
Let's take a look at protection:
[*] '/home/tasike/Desktop/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
executable: 0x55c44ae0083a
system@plt: 0x7fae8e850d70
heap: 0x55c44cb212a0
stack: 0x7ffec748e904
As you can see, the protection has been fully turned on and the address has been completely randomized!
Here is your flag:
ctfshow{Address_Space_Layout_Randomization&&Position-Independent_Executable_1s_C0000000000l!}

```

对比前后的地址，确实是不同的：

> executable: 0x5650c4a0083a 	0x55c44ae0083a
> system@plt: 0x7f46c1050d70 	0x7fae8e850d70
> heap: 0x5650c67b22a0 	0x55c44cb212a0
> stack: 0x7ffc8a4a7254  0x7ffec748e904

ASLR和PIE开启后，地址都会将随机化，这里值得注意的是，由于粒度问题，虽然地址都被随机化
了，但是被随机化的都仅仅是某个对象的起始地址，而在其内部还是原来的结构，也就是相对偏移是不
会变化的。