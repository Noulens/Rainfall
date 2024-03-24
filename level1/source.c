#include <stdio.h>
#include <stdlib.h>

void	run()
{
	const char	*str = "Good... Wait what?\n";
	const char	*cmd = "/bin/sh";

	fwrite(str, 1, 19, stdin);
	system(cmd);
	return ;
}

void	main()
{
	char	str[64];

	gets(str);
	return ;
}
