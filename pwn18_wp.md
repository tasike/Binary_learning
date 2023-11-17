> 这题还是挺阴险的，只要连接上靶场后第一次输入错，就别想通过这个靶场得到答案了，只能再次申请一个靶场。
>
> 回到这题的解答，首先自然是查看基本信息：
> ```
> tasike@tasike-VM:~/Desktop$ file pwn18
> pwn18: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=465c5bef834733cbe321eaebac19bae8888fbb6e, not stripped
> tasike@tasike-VM:~/Desktop$ checksec pwn18
> [*] '/home/tasike/Desktop/pwn18'
>     Arch:     amd64-64-little
>     RELRO:    Full RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      PIE enabled
> ```
>
> 由上可知：64位保护全开
>
> 用ida64打开pwn18：
> ```c
> int __cdecl main(int argc, const char **argv, const char **envp)
> {
>   int v4; // [rsp+4h] [rbp-Ch] BYREF
>   unsigned __int64 v5; // [rsp+8h] [rbp-8h]
> 
>   v5 = __readfsqword(0x28u);
>   setvbuf(_bss_start, 0LL, 2, 0LL);
>   setvbuf(stdin, 0LL, 1, 0LL);
>   puts(s);
>   puts(asc_B10);
>   puts(asc_B90);
>   puts(asc_C20);
>   puts(asc_CB0);
>   puts(asc_D38);
>   puts(asc_DD0);
>   puts("    * *************************************                           ");
>   puts(aClassifyCtfsho);
>   puts("    * Type  : Linux_Security_Mechanisms                               ");
>   puts("    * Site  : https://ctf.show/                                       ");
>   puts("    * Hint  : Do you know redirect output ?                           ");
>   puts("    * *************************************                           ");
>   puts("Which is the real flag?");
>   __isoc99_scanf("%d", &v4);
>   if ( v4 == 9 )
>     fake();
>   else
>     real();
>   system("cat /ctfshow_flag");
>   return 0;
> }
> ```
>
> 关键代码在22行到30行，要求键入一个数字，如果键入9，那么执行fake函数；如果不是9，那么执行real函数。但是无论如何，都会执行28行的命令。因此跟进以下fake和real：
> ```c
> int fake()
> {
>   return system("echo 'flag is here'>>/ctfshow_flag");
> }
> ```
>
> ```c
> int real()
> {
>   return system("echo 'flag is here'>/ctfshow_flag");
> }
> ```
>
> 乍一看，这俩函数一样？
>
> no,no,no！fake函数用的命令是>>，而real函数用的命令是>
>
> #### 这就涉及到细节问题：
>
> 1. ```
>    echo 'flag is here'>>/ctfshow_flag
>    ```
>
>    这个命令将字符串'flag is here'==追加==写入/ctfshow_flag文件中。
>
>    ==>>==符号表示以==追加==的方式写入文件，如果文件不存在则创建新文件。如果/ctfshow_flag文件已经存在，那么该命令会在文件的末尾追加'flag is here'。
>
>    而且追加的方式是换一行然后写入，如下：
>
>    ```
>    tasike@tasike-VM:~/Desktop$ echo 'hello'>>hello
>    tasike@tasike-VM:~/Desktop$ cat hello
>    hello
>    tasike@tasike-VM:~/Desktop$ echo 'hello'>>hello
>    tasike@tasike-VM:~/Desktop$ cat hello
>    hello
>    hello
>    ```
>
> 2. ```
>    echo 'flag is here'>/ctfshow_flag
>    ```
>
>    这个命令将字符串'flag is here'==覆盖==写入/ctfshow_flag文件中。
>
>    ==>==符号表示以==覆盖==的方式写入文件，如果文件不存在则创建新文件，如果/ctfshow_flag文件已经存在，那么该命令会将文件中原有的内容替换为'flag is here'。
>
> **因此，只有执行fake函数才能保证ctfshow_flag文件的原有内容不被覆盖，必须键入9。同时，当连接上靶场之后第一次没有键入9，第二次键入9的时候ctfshow_flag文件已经被覆盖，因此也得不到答案，必须销毁容器，再次申请一个新的靶场。**
>
> ```
> tasike@tasike-VM:~/Desktop$ nc pwn.challenge.ctf.show 28113
>     ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
>   ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
>  ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
>  ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
>  ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
>   ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
>     ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  
>     * *************************************                           
>     * Classify: CTFshow --- PWN --- 入门                              
>     * Type  : Linux_Security_Mechanisms                               
>     * Site  : https://ctf.show/                                       
>     * Hint  : Do you know redirect output ?                           
>     * *************************************                           
> Which is the real flag?
> 9
> ctfshow{ab970a69-1936-46dc-91ff-cbb4a4f9243c}
> flag is here
> ```
>
> ctfshow{ab970a69-1936-46dc-91ff-cbb4a4f9243c}