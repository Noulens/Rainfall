#include <stdlib.h>
#include <string.h>

char	*p(char *str1, char *str2)
{
	char	buffer[4096];

	puts(str2);
	read(0, buffer, 4096);
	*strchr(buffer, '\n') = 0;
	return (strncpy(str1, buffer, 20));
}

char	*pp(char *buffer)
{
	char			s1[20];
	char			s2[20];
	unsigned int	len;

	p(s1, " - ");
	p(s2, " - ");
	strcpy(buffer, s1);
	len = strlen(buffer);
	buffer[len] = ' ';
	buffer[len + 1] = 0;
	return (strcat(buffer, s2));
}

int		main(void)
{
	//0x40 - 0x16 = 42 bytes
	char	buffer[42];

	pp(buffer);
	puts(buffer);
	return (0);
}