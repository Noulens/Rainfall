#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define _GNU_SOURCE

int main(int argc, char **argv)
{
	if (atoi(argv[1]) == 0x1a7)
	{
		char	*sh = "/bin/sh";
		char	*cmd = strdup(sh);
		char	*args[2];
		__gid_t	egid = getegid();
		__uid_t	uid = geteuid();

		egid = getegid();
		uid = geteuid();
		setresgid(egid, egid,egid);
		setresuid(uid, uid, uid);
		args[0] = sh;
		args[1] = NULL;
		execv(cmd, args);
	}
	else
	{
		fwrite("No !\n", 1, 5, stderr);
	}
	return (0);
}
