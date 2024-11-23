#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  // stack_size = 0xa0 = 160
  FILE *file;       // esp+0x9c
  char str1[132];   // esp+0x18
  char unknown[24]; // esp+0x00

  file = fopen("/home/user/end/.pass", "r");

  memset(str1, 0, 132 /* 0x21 * 4 */);

  if (file == NULL || argc != 2) {
    return 0xffffffff;
  }

  fread(str1, 1, 66 /* 0x42 */, file);
  str1[65 /* 0x59 - 0x18 */] = 0;

  str1[atoi(argv[1])] = 0;

  fread(&str1[66 /* 0x42 */], 1, 65 /* 0x41 */, file);
  fclose(file);

  if (strcmp(str1, argv[1]) == 0) {
    execl("/bin/sh", "sh", 0);
  } else {
    puts(&str1[66 /* 0x42 */]);
  }

  return 0;
}