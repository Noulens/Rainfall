#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int _, char *argv[])
{
    const int first_arg = atoi(argv[1]);
    if (first_arg == 0x1a7) { // 423
        char *cmd = strdup("/bin/sh");

        const gid_t gid = getegid();
        const uid_t uid = geteuid();

        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);

        execv("/bin/sh", &cmd);
    }
    else {
        fwrite("No !\n", 1, 5, stderr);
    }
    return 0;
}
