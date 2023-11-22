> 首先常规查看**文件位数**，**是否动态链接**，**开启了哪些保护机制**
>
> ```
> tasike@tasike-VM:~/Desktop$ file pwn4
> pwn4: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f0b85e8d76ea7a4710ee1d4eff80c151292343cb, not stripped
> ```
>
> ==由上可知：64位，动态链接(dynamically linked)==
>
> ```
> tasike@tasike-VM:~/Desktop$ checksec pwn4
> [*] '/home/tasike/Desktop/pwn4'
>     Arch:     amd64-64-little
>     RELRO:    Full RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      PIE enabled
> ```
>
> ==由上可知：开启了全局只读保护，Canary保护，堆栈不可执行保护，地址随机化保护==
>
> 接着用ida64查看反编译该文件：
>
> ```c
> int __cdecl main(int argc, const char **argv, const char **envp)
> {
>   char s1[11]; // [rsp+1h] [rbp-1Fh] BYREF
>   char s2[12]; // [rsp+Ch] [rbp-14h] BYREF
>   unsigned __int64 v6; // [rsp+18h] [rbp-8h]
> 
>   v6 = __readfsqword(0x28u);
>   setvbuf(_bss_start, 0LL, 2, 0LL);
>   setvbuf(stdin, 0LL, 2, 0LL);
>   strcpy(s1, "CTFshowPWN");
>   logo();
>   puts("find the secret !");
>   __isoc99_scanf("%s", s2);
>   if ( !strcmp(s1, s2) )
>     execve_func();
>   return 0;
> }
> ```
>
> ==可以看到，第10行，字符数组s1被赋值为"CTFshowPWN"，logo函数点进去没什么用，就是一堆puts，接着可以看到if的语句中有execve_func函数，看起来很可疑，点进去查看：==
>
> ```c
> unsigned __int64 execve_func()
> {
>   char *argv[3]; // [rsp+0h] [rbp-20h] BYREF
>   unsigned __int64 v2; // [rsp+18h] [rbp-8h]
> 
>   v2 = __readfsqword(0x28u);
>   argv[0] = "/bin/sh";
>   argv[1] = 0LL;
>   argv[2] = 0LL;
>   execve("/bin/sh", argv, 0LL);
>   return __readfsqword(0x28u) ^ v2;
> }
> ```
>
> ==因此这题有很明显的后门函数，也就是我们只需要让if的条件为真，就可以getshell，从而获得最高权限==
>
> ==要让条件为真也很容易，只要两个字符串相等就行，因此，当scanf输入的时候，输入CTFshowPWN即可==