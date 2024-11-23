Ce coup ci, on a un programme qui lis un buffer de 512 bytes avec fgets et qui affiche ce buffer avec printf.
Ensuite le programme verifie la valeur d'une variable globale et si elle est egale a 0x40, il execute un shell.

On peut donc utiliser une vulnerabilite de printf pour ecrire la valeur 0x40 (= 64) dans la variable globale.

Pour cela, il faut comprendre le fonctionnement des arguments de printf:
- Chaque %_ est un argument, qui cause une lecture sur la stack (esp, esp+4, esp+8, ...)
- Ainsi on peut lire des valeurs presentes sur la stack sans limitations
- On peut aussi ecrire des valeurs (int) avec le flag %n. Ce flag ecrit le nombre de caracteres ecrits jusque la dans l'argument correspondant
=> On peut donc ecrire des valeurs a des adresses arbitraires si elles sont presentes sur la stack

En analysant le binaire via gdb/objdump, on voit que l'adresse de la variable globale 'm' est 0x0804988c.
Ensuite en executant le programme en passant plein de %8x (valeur hex de l'argument, pad a 8 characteres) a printf, on voit que le debut de notre buffer debute a esp+12 (4e argument de printf)
On peut donc ecrire a l'adresse de 'm' en utilisant le flag %n.

La strategie est donc la suivante:
- On fait en sorte que printf affiche 64 caracteres (0x40) avant d'arriver au %n
- Il faut pop 3 arguments de la stack pour arriver a l'adresse de 'm' au moment du %n
- Il faut ecrire l'addresse de 'm' dans la stack pour que %n ecrive la valeur 0x40 a l'adresse de 'm'
- On a observe que notre buffer commence a esp+12, donc on peut ecrire l'adresse de 'm' au debut de notre buffer.

Pour arriver a 64:
- 4 characters pour l'adresse de 'm'
- 60 - (8 x 3) = 36 characteres au pif
- 3 %8x qui donnent donc les (3 x 8) = 24 derniers characteres
=> 4 + 36 + 24 = 64

Ainsi on obtient l'exploit suivant:
```bash
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08' + 'A'*(60-(3*8)) + '%8x'*3 + '%n'" > /tmp/payload3
level3@RainFall:~$ cat /tmp/payload3 - | ./level3
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA     200b7fd1ac0b7ff37d0
Wait what?!
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```