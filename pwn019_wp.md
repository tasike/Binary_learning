```
这题算是考察比较多Linux系统的知识，可以借此好好学习一下。

了解Linux怎样处理输入和输出是非常重要的。一旦我们了解其原理以后，我们就可以正确熟练地使用脚本把内容输出到正确的位置。同样我们也可以更好地理解输入重定向和输出重定向。
```

### Linux标准文件描述符（fd）

| 文件描述符(fd) |  缩写  |     描述     |
| :------------: | :----: | :----------: |
|       0        | STDIN  |   标准输入   |
|       1        | STDOUT |   标准输出   |
|       2        | STDERR | 标准错误输出 |

```
Linux系统将所有设备都当作文件来处理，而Linux用文件描述符来标识每个文件对象。也就是说，无论是电脑的显示器，还是键盘，在Linux中都被看作是文件，它们都有相应的文件描述符与之对应。
我认为兴许可以用本身带有作用(比如0的作用是标准输入)的指针(不过这里的指针仅仅是概念上类似C语言中的指针,在用法上,此处的指针利用&来实现引用,而C语言中的指针利用*来实现引用)来理解，文件描述符0是指向键盘(键盘被视为文件)的指针,文件描述符1是指向显示器(显示器被视为文件)的指针,文件描述符2和文件描述符1指向同一个位置，也就是显示器。
但是，上述的这些指向(0,1,2)都是默认的,也就是可以修改它们的指向。
```

```
下面的命令就是把标准输出的位置修改到aaa文件中：
tasike@tasike-VM:~/Desktop$ exec 1>a
tasike@tasike-VM:~/Desktop$ ls
tasike@tasike-VM:~/Desktop$ 
命令执行后，文件描述符1指向aaa文件，那么接下去在当前shell下的所有输出将不再显示器中输出，而是在aaa文件中输出
当前shell中输入ls是没有任何输出结果的,这是因为输出的指向不是显示屏,而是aaa文件,为了验证是否输出到aaa文件中,我们重新打开一个shell(必须重新打开一个shell,因为你在当前shell里由于不能输出,因此cat aaa命令仍然无效),在新的shell中：
tasike@tasike-VM:~/Desktop$ cat a
a
attack_format_level0.py
attack_format_level1.py
attack_format_level3.py
attack_little_canary.py
attack_name4.py
attack_PIE_enabled.py
attack_play.py
attack_rePWNse.py
attack_ret2libc.py
attack_ret2syscall.py
attack_ret2text_32.py
attack_ret2text_64.py
attack_shellcode_level0.py
attack_shellcode_level1.py
attack_shellcode_level2.py
attack_shellcode_level3.py
attack_uninitialized_key_plus.py
attack_uninitialized_key.py
attack_woof.py
CGfsb
CGfsb_exp.py
checksec.sh
exp.py
f1ag
fd.c
fork.c
format_level0
format_level1
format_level3
heap_Easy_Uaf
level0_exp.py
level2_exp.py
LibcSearcher
LibcSearcher.py
libc.so.6
little_canary
name4
PIE_enabled
play
proc
pwn
pwn19
pwn20
pwn35
pwn6
pwndbg
__pycache__
rePWNse
ret2libc
ret2syscall
ret2text_32
ret2text_64
shellcode_level0
shellcode_level1
shellcode_level2
shellcode_level3
test
test.c
test_int_overflow.c
test.py
uninitialized_key
uninitialized_key_plus
VMwareTools-10.3.25-20206839.tar.gz
vmware-tools-distrib
woof
```

```
Pay Attention:重定向有两种方式(fd表示文件描述符,file表示文件名)：
第一种：exec fd>file
第二种：exec fd1>&fd2
也就是说,当重定向为另一个文件描述符所指向的文件的时候,引用使用的是&,这不同于C语言的*
```

```
下面用一个更为复杂的例子来整理一下思路：
exec 3>&1
exec 1>test
echo "这句话被存到test文件中"
echo "还有这句"
exec 1>&3
echo "这句话输出到显示器"

对上述的命令作出解释：首先文件描述符1默认指向的是显示器,用&来找到文件描述符指向的目标文件,也就是显示器。因此文件描述符3也指向了显示器。然后，我们修改了文件描述符1使之指向test文件。接着两个echo命令的输出会自然去找文件描述符1(因为文件描述符1就是标准输出),然后由于文件描述符1指向test文件,因此它会把输出写到test文件中。最后，我们用&来找到文件描述符3指向的目标文件，也就是显示器。然后我们修改了文件描述符1使之指向显示器。因此，最后一个echo命令会自然去找文件描述符1然后输出到显示器上。
```

```
下面介绍一些与文件描述符相关的一些shell命令，这可以使我们如虎添翼。
```

### 文件描述符相关的一些shell命令

```
tasike@tasike-VM:~/Desktop$ lsof -a -p $$ -d 0,1,2
COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
bash    5413 tasike    0u   CHR  136,0      0t0    3 /dev/pts/0
bash    5413 tasike    1u   CHR  136,0      0t0    3 /dev/pts/0
bash    5413 tasike    2u   CHR  136,0      0t0    3 /dev/pts/0
```

| Column  | Description                                                  |
| :------ | :----------------------------------------------------------- |
| COMMAND | The first nine characters of the name of the command in the process |
| PID     | The process ID of the process                                |
| USER    | The login name of the user who owns the process              |
| FD      | The file descriptor number and access type(r - read, w - write, u - read/write) |
| TYPE    | The type of file(CHR - character, BLK - block, DIR - directory, REG - regular file) |
| DEVICE  | The device numbers(major and minor) of the device            |
| SIZE    | If available, the size of the file                           |
| NODE    | The node number of the local file                            |
| NAME    | The name of the file                                         |

> 以上笔记来自于[Linux 文件描述符详解-CSDN博客](https://blog.csdn.net/xlinsist/article/details/51147212)

```
回到题目，这题是用fclose关闭了输出流，因此，为了能够恢复输出，我们选择采用重定向的手段，将文件描述符1指向文件描述符0所指向的文件，从而恢复了在显示屏上进行标准输出，在Linux下测试如下：
```

```
tasike@tasike-VM:~/Desktop$ touch a
tasike@tasike-VM:~/Desktop$ exec 1>a
tasike@tasike-VM:~/Desktop$ exec 1>&0
tasike@tasike-VM:~/Desktop$ ls
a                                 checksec.sh      pwn35
attack_format_level0.py           exp.py           pwn6
attack_format_level1.py           f1ag             pwndbg
attack_format_level3.py           fd.c             __pycache__
attack_little_canary.py           fork.c           rePWNse
attack_name4.py                   format_level0    ret2libc
attack_PIE_enabled.py             format_level1    ret2syscall
attack_play.py                    format_level3    ret2text_32
attack_rePWNse.py                 heap_Easy_Uaf    ret2text_64
attack_ret2libc.py                level0_exp.py    shellcode_level0
attack_ret2syscall.py             level2_exp.py    shellcode_level1
attack_ret2text_32.py             LibcSearcher     shellcode_level2
attack_ret2text_64.py             LibcSearcher.py  shellcode_level3
attack_shellcode_level0.py        libc.so.6        test
attack_shellcode_level1.py        little_canary    test.c
attack_shellcode_level2.py        name4            test_int_overflow.c
attack_shellcode_level3.py        PIE_enabled      test.py
attack_uninitialized_key_plus.py  play             uninitialized_key
attack_uninitialized_key.py       proc             uninitialized_key_plus
attack_woof.py                    pwn              VMwareTools-10.3.25-20206839.tar.gz
CGfsb                             pwn19            vmware-tools-distrib
CGfsb_exp.py                      pwn20            woof
tasike@tasike-VM:~/Desktop$ cat a
tasike@tasike-VM:~/Desktop$ 
```

```
上述例子虽然没有直接关闭输出流，但是，把文件描述符1重定向到a文件中，事实上也算是在当前shell中关闭了标准输出流(即输出到显示屏上)。但是我们将文件描述符1重定向到文件描述符0所指向的文件之后，显然ls可以输出，并且可以发现并没有任何输出写到a中。因此，这种重新开启输出流的手段是可行的。
```

```
那么这道题就可以通过这种重新开启输出流的方式来获取flag。
asike@tasike-VM:~/Desktop$ nc pwn.challenge.ctf.show 28288
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
    * Hint  : Turn off output, how to get flag? 
    * *************************************                           
give you a shell! now you need to get flag!
exec cat /ctfshow_flag 1>&0
ctfshow{cccabd2e-6972-44d8-a73e-f333c1636bdd}
flag is not here!
```

```
事实上，这题还是挺仁慈的，因为它的read读入的长度是0x20ULL,也就是它接受你输入不多于32个字符的数据，我们上面的输入了27个，也就是完全够我们把完整的命令输完。这题还有改难的空间，也就是可以限制read的读入长度，我认为
exec cat /ctf* 1>&0
就够了，也就是限制读入长度为19个字符，也就是0x13ULL，该题也是可解的，但是难度肯定是增加了。
```

> 还可以参考这篇文章：[exec 1>&0-CSDN博客](https://blog.csdn.net/xirenwang/article/details/104139866?ops_request_misc=%7B%22request%5Fid%22%3A%22169781235116800222899823%22%2C%22scm%22%3A%2220140713.130102334..%22%7D&request_id=169781235116800222899823&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-104139866-null-null.142^v96^pc_search_result_base9&utm_term=1>%260&spm=1018.2226.3001.4187)该文章中的末尾还有一些其他的参考文章。

==事实上这题还涉及fork的父子进程问题，就等以后有时间或者找到某篇好的文章再来填坑吧！（狗头保命）==

