Bon a priori il faut decompiler les executables pour recuperer le flag.  
Fort heureusement, ghidra est un outil tres pratique pour cela.  
Il suffit de lancer ghidra, de creer un nouveau projet, d'importer l'executable et de l'analyser.  
Apres analyse et quelques renommages, on obtient cela:

```c++
int main(int argc, char **argv)

{
  int first_arg;
  char *cmd;
  undefined4 useless;
  __uid_t uid;
  __gid_t gid;
  
  first_arg = atoi(*(argv + 4));
  if (first_arg == 0x1a7) {
    cmd = strdup("/bin/sh");
    useless = 0;
    gid = getegid();
    uid = geteuid();
    setresgid(gid,gid,gid);
    setresuid(uid,uid,uid);
    execv("/bin/sh",&cmd);
  }
  else {
    fwrite("No !\n",1,5,(FILE *)stderr);
  }
  return 0;
}
```

Et rendu joli et lisible, on obtient ce que j'ai dans `source.c`

Ainsi on voit que le programme compare le premier argument avec 0x1a7 (423 en decimal) et si c'est bon, il execute un shell (en tant que level1, car le s-bit est active :D).

```bash
$ ./level0 423
$ cd ../level1
$ cat .pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

Et voila :)