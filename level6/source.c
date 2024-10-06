#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void	n()
{
	system("/bin/cat /home/user/level7/.pass");
}

void    m()
{
	puts("Nope");
}

void	main(int argc, char **argv)
{
	(void)argc;
	char	*buffer1 = malloc(64);
	void	(*func_ptr)() = malloc(4);

	func_ptr = m;
	argv++;
	strcpy(buffer1, *argv);
	func_ptr();
	return ;
}
