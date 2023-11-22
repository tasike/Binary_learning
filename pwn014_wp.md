> 打开flag.c文件查看源码：
> ```c
> #include <stdio.h>
> #include <stdlib.h>
> 
> #define BUFFER_SIZE 1024
> 
> int main() {
>  FILE *fp;
>  unsigned char buffer[BUFFER_SIZE];
>  size_t n;
>  fp = fopen("key", "rb");
>  if (fp == NULL) {
>      perror("Nothing here!");
>      return -1;
>  }
>  char output[BUFFER_SIZE * 9 + 12]; 
>  int offset = 0;
>  offset += sprintf(output + offset, "ctfshow{");
>  while ((n = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, fp)) > 0) {
>      for (size_t i = 0; i < n; i++) {
>          for (int j = 7; j >= 0; j--) {
>              offset += sprintf(output + offset, "%d", (buffer[i] >> j) & 1);
>          }
>          if (i != n - 1) {
>              offset += sprintf(output + offset, "_");
>          }
>      }
>      if (!feof(fp)) {
>          offset += sprintf(output + offset, " ");
>      }
>  }
>  offset += sprintf(output + offset, "}");
>  printf("%s\n", output);
>  fclose(fp);
>  return 0;
> }
> ```
>
> ```
> 程序打开名为 "key" 的文件，以二进制（"rb"）模式进行读取。如果文件打开失败，将执行if中的语句，输出 "Nothing here!" 并返回 -1。
> 然后，程序定义了一个缓冲区 buffer 用于读取文件内容，以及一个字符串数组 output 用于存储转换后的二进制字符串。变量 offset 用于跟踪 output 数组中的偏移量。
> 接下来，程序开始将输出字符串初始化为 "ctfshow{"，然后进入一个循环，每次读取 BUFFER_SIZE 字节的数据到 buffer 中，并将其转换为二进制字符串形式。
> 在内层循环中，程序遍历当前读取的字节的每一位，从最高位到最低位。通过右移操作和位与运算，提取出每一位的值，并使用 sprintf 函数将其添加到 output 字符串中。
> 在每个字节的二进制表示结束后，如果当前字节不是最后一个字节，则在 output 字符串中添加下划线作为分隔符。如果文件还未读取完毕（即文件结束符未被读取），则在 output 字符串中添加空格作为分隔符。
> 循环结束后，程序在 output 字符串中添加 "}"，表示结束标记，并使用 printf 函数将最终的转换结果打印出来。最后，程序关闭文件，并返回 0 表示成功执行。
> 该程序的作用是将二进制文件中的内容转换为二进制字符串形式，并以特定格式输出
> ```
>
> 因此，当我们把flag.c文件复制到Linux中后，为了不执行第一个if语句，需要在flag.c所在目录下先建立一个key，根据题目所说，key是"CTFshow"。
>
> 这不得不说一个小插曲，就是我在本地打的时候，就发现一直执行if语句的内容然后退出，导致我以为是有什么问题，事实就是本地本来是没有flag文件的，所以自然打不开。
>
> ```
> tasike@tasike-VM:~/Desktop$ echo "CTFshow">key
> tasike@tasike-VM:~/Desktop$ gcc -o proc flag.c
> tasike@tasike-VM:~/Desktop$ ./proc
> ctfshow{01000011_01010100_01000110_01110011_01101000_01101111_01110111_00001010}
> ```
>
> ==这里需要学习的就是echo把字符串"CTFshow"重定向到key，之前我是直接touch key之后再open key然后再输入CTFshow，但是打不通，因此要注意使用echo重定向指令。==