#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int m = 0;

void o() {
  // stack: 0 -> 24 [opti compilo?]
  system("/bin/sh" /* 0x80485f0 */);
  _exit(1 /* 0x1 */);
}

void n(void) {
  // stack: 0 -> 8 [opti compilo?]
  char buf[512]; // stack: 8 -> 520
  // stack: 520 -> 536 [opti compilo?]

  fgets(buf /* ebp-0x208 */, 512 /* 0x200 */, stdin /* ds:0x8049848 */);
  printf(buf /* ebp-0x208 */);
  exit(1 /* 0x1 */);
}

void main(void) {
  n();
}