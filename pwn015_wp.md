> 使用以下命令==将汇编代码编译为目标文件==:
>
> ```
> tasike@tasike-VM:~/Desktop$ nasm -f elf flag.asm -o flag.o
> ```
>
> 查看flag.o的位数，以确定以那种架构进行链接：
>
> ```
> tasike@tasike-VM:~/Desktop$ file flag.o
> flag.o: ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped
> ```
>
> 使用以下命令==将目标文件链接为可执行文件==：
>
> ```
> tasike@tasike-VM:~/Desktop$ ld -m elf_i386 -o flag flag.o
> ```
>
> 执行即可得到flag:
>
> ```
> tasike@tasike-VM:~/Desktop$ ./flag
> ctfshow{@ss3mb1y_1s_3@sy}
> ```
>
> 