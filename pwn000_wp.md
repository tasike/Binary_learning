> 这道题吧，直接连接靶场，然后就得到shell了。
>
> 不过有一些细节问题：
>
> - 一开始我是直接输入ls命令，结果是什么也没有显示
> - 因此，需要注意的是，含有flag的文件不一定在当前目录，还可能在根目录
> - 所以，要用ls /命令，查看根目录下的文件
> - 成功查看后发现确实有ctfshow_flag文件，但是同样地，打开不能直接cat ctfshow_flag，因为不在该文件的目录下，所以要使用cat /ctfshow_flag