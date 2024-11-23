#include <stdio.h>
#include <stdlib.h>

int m = 0;

void v(void) {
  // stack: 0 -> 8 [opti compilo?]
  char buf[512]; // stack: 8 -> 520
  // stack: 520 -> 536 [opti compilo?]

  fgets(buf /* [ebp-0x208] */, 512 /* 0x200 */, stdin /* ds:0x8049860 */);
  printf(buf  /* [ebp-0x208] */);

  if (m == 64 /* 0x40 */) {
    fwrite("Wait what?!\n" /* 0x8048600 */, 1 /* 0x1 */, 12 /* 0xC */, stdout /* ds:0x8049880 */);
    system("/bin/sh" /* 0x804860d */);
  }
}

void main(void) {
  v();
}