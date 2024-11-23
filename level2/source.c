#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void p(void) {
    // stack: 0 -> 12 [opti compilo?]
    char buf[64];       // stack: 12 -> 76
    // stack: 80 -> 104 [opti compilo?]
    fflush(stdout);

    gets(buf);
    void *a = __builtin_return_address(0); // stack: 76 -> 80
    if (((uint)a & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", a);
        exit(1);
    }
    puts(buf);
    strdup(buf);
}

void main(void)
{
    p();
}