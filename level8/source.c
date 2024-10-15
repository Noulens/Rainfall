#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

char	*auth = NULL;
char	*service = NULL;

void	main(void)
{
	char	buffer[128];

	while (1)
	{
		printf("%p, %p \n", auth, service);
		if (fgets(buffer, 128, stdin) == NULL)
			break;
		if (strncmp(buffer, "auth ", 5) == 0)
		{
			auth = malloc(4);
			*auth = 0x0;
			if (strlen(buffer + 5) <= 30)
			{
				strcpy(auth, buffer + 5);
			}
		}
		if (strncmp(buffer, "reset", 5) == 0)
		{
			free(auth);
		}
		if (strncmp(buffer, "service", 6) == 0)
		{
			service = strdup(buffer + 7);
		}
		if (strncmp(buffer, "login") == 0)
		{
			if (auth[32] != 0)
				system("/bin/sh");
			else
				fwrite("Password:\n", 1, 10, stdout);
		}
	}
	exit (0);
}
