#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int i = 0;

int v(void)
{
	char	buffer[512];

	fgets(buffer, 512, stdin);
    printf(buffer);
    if (i == 64)
    {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
    return (0);
}

int		main(void)
{
	v();
	return (0);
}