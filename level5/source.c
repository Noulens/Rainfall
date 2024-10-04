#include <stdio.h>
#include <stdlib.h>

void    o()
{
    system("/bin/sh");
    _exit(0);
}

int n()
{
    char    buffer[512];

    fgets(buffer, 512, stdin);
    printf(buffer);
    exit(1);
}

int main(void)
{
    n();
    return (0);
}
