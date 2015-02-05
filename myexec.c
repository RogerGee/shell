/* myexec.c - run a command specified by the user */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

int main(int argc,const char* argv[])
{
    if (argc <= 1) {
        fprintf(stderr,"usage: %s command args ...\n",argv[0]);
        return 1;
    }
    execvp(argv[1],(char* const*)argv+1);
    fprintf(stderr,"%s: command failed: %s\n",argv[0],strerror(errno));
    return 0;
}
