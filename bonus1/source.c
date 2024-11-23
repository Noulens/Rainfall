#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  int amountOfBytes;
  char buffer[40];

  if ((amountOfBytes = atoi(argv[1])) <= 9) {
    memcpy(buffer, argv[2], amountOfBytes * 4);
    if (amountOfBytes == 0x574f4c46) {
      execl("/bin/sh", "sh", 0);
    }
    return 0;
  }
  return 1;
}