#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68];

void	m(void)
{
	int t = time(NULL);
	printf("%s - %d\n", c, t);
}

int	main(int ac, char **av)
{
	int	*b1;
	int	*b2;

	b1 = malloc(8);
	*b1 = 1;
	*(b1 + 1) = malloc(8);
	b2 = malloc(8);
	*b2 = 2;
	*(b2 + 1) = malloc(8);
	strcpy(*(b1 + 1), av[1]);
	strcpy(*(b2 + 1), av[2]);
	fgets(c, 64, fopen("/home/user/level8/.pass", "r"));
	puts("~~");
	return (0);
}

