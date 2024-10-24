#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int language = 0;

int greetuser(const char *username)
{
	// stack_size = 88 | 0x58
	char str[72];     // esp+0x10 | ebp-0x48

	if (language == 1)
		strcpy(str, "\x48\x79\x76\xc3\xa4\xc3\xa4\x20\x70\xc3\xa4\x69\x76\xc3\xa4\xc3\xa4\x20");
	else if (language == 2)
		strcpy(str, "Goedemiddag!  ");
	else if (language == 0)
		strcpy(str, "Hello ");
	strcat(str, username);
	return puts(str);
}

int main(const int argc, char *argv[], char *env[])
{
	// stack_size = 160 | 0xa0
	char *env_lang; // esp+0x9c
	char str1[76];  // esp+0x50
	char str2[76]; // esp+0x0

	if (argc != 3)
		return 1;
	memset(str1, 0, 76 /* 0x13 * 4 */);
	strncpy(str1, argv[1], 40 /* 0x28 */);
	strncpy(&str1[40 /* 0x28 */], argv[2], 32 /* 0x20 */);
	env_lang = getenv("LANG");
	if (env_lang != NULL)
	{
		if (memcmp(env_lang, "fi", 2) == 0)
			language = 1;
		else if (memcmp(env_lang, "nl", 2) == 0)
			language = 2;
	}
	memcpy(str2, str1, 76 /* 0x13 * 4 */);
	return greetuser(str2);
}