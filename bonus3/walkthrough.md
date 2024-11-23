Le programme demande exactement un argument, qui sera parse par `atoi`.
On voit que dans la globalite, le programme lis le fichier `.pass` de l'utilisateur `end`,  
Ensuite il copie le contenu dans un buffer et mets un `\0` au 66eme charactere.  
Juste apres il mets un `\0` au `atoi(argv[1])`eme charactere.
Ensuite il compare le buffer avec `argv[1]` et si c'est le meme, il execute un shell.
Le reste importe peu.  

L'exploit ici est que `atoi("")` retourne `0`, donc le programme va mettre un `\0` au 0eme charactere,
Ainsi le `strcmp` va retourner `0` et le shell va etre execute.  

```bash
bonus3@RainFall:~$ ./bonus3 ""
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$
```