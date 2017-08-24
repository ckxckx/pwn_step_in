#include <stdio.h>
#include <unistd.h>
char buf[10] = "/bin/sh\x00";
int main()
{
    char s[0x100];
    puts("input something you want: ");
    read(0, s, 0x400);
    return 0;
}
