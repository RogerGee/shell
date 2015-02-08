/* shell.c - implements a simple shell for MINIX */
#include "proc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

const char* programName;
void raise_exception(const char* message);

static void message_loop();
static void print_prompt(int normalPrompt);
static const char* get_working_directory();
static int cd(const char* directory);
/*static int pud(const char* directory);
  static int pod();*/
static int readline(FILE* fin,char* buf,size_t cap);

int main(int argc,const char* argv[])
{
    programName = argv[0+(argc-argc)];

    message_loop();
    return 0;
}

void raise_exception(const char* message)
{
    fprintf(stderr,"%s: exception: %s\n",programName,message);
    exit(EXIT_FAILURE);
}

void message_loop()
{
    int exitCode;
    char cmdline[4096];
    struct cmdargv* tokens;             /* store command-line tokens */
    struct job_argv_buffer* j_tokens;  /* store series of command-line tokens for job */
    tokens = cmdargv_new();
    j_tokens = job_argv_buffer_new();

    while (1) {
        int c = 0;
        const char* const* argv;
        do {
            print_prompt(!c++);

            if ( !readline(stdin,cmdline,sizeof(cmdline)) )
                /* received end-of-file on stdin */
                goto done;
        } while ( !cmdargv_parse(tokens,cmdline) );

        argv = cmdargv_get_argv(tokens);
        if (argv[0] != NULL) {
            /* check built-in commands first; otherwise run external command(s) */
            if (strcmp(argv[0],"cd") == 0)
                cd(argv[1]);
            else if (strcmp(argv[0],"exit") == 0)
                break;
            else {
                if (job_argv_buffer_transform(j_tokens,tokens)) {

                }
                job_argv_buffer_reset(j_tokens);
            }
        }

        cmdargv_reset(tokens);
    }

done:
    job_argv_buffer_free(j_tokens);
    cmdargv_free(tokens);
    putchar('\n');
}

void print_prompt(int normalPrompt)
{
    if (normalPrompt) {
        const char* user, *cwd;
        /* get user name from environment */
        user = getenv("USER");
        cwd = get_working_directory();
        printf("[%s] %s$ ",user,cwd);
    }
    else
        printf(" -> ");
}

const char* get_working_directory()
{
    static size_t alloc = 256;
    static char* buffer = NULL;
    size_t len;
    const char* home;
    if (buffer == NULL)
        buffer = malloc(alloc);
    /* get home directory from path */
    home = getenv("HOME");
    /* get current working directory */
    while (getcwd(buffer,alloc) == NULL) {
        if (errno == ENOENT) {
            /* current directory is no longer in file system */
            strcpy(buffer,"~unlinked~");
            break;
        }
        if (errno == ERANGE) {
            /* CWD is too long for buffer; try to make buffer bigger */
            alloc <<= 1;
            if (realloc(buffer,alloc) == NULL) {
                strcpy(buffer,"~no-memory~");
                break;
            }
        }
        else if (errno == EACCES) {
            strcpy(buffer,"~access-denied~");
            break;
        }
        else {
            strcpy(buffer,"~error~");
            break;
        }
    }
    if (home != NULL) {
        /* if working directory substring starting at position 0 matches home directory, then
           replace with '~' character */
        len = strlen(home);
        if (strncmp(buffer,home,len) == 0) {
            size_t i, l = strlen(buffer+len);
            buffer[0] = '~';
            for (i = 0;i <= l;++i)
                buffer[i+1] = buffer[len+i];
        }
    }
    return buffer;
}

int cd(const char* directory)
{
    /* interpret cmdline as new directory for shell */
    const char* home;
    home = getenv("HOME");
    if (directory == NULL) {
        if (home != NULL) {
            if (chdir(home) == -1) {
                fprintf(stderr,"%s: cd: '%s': %s\n",programName,home,strerror(errno));
                return 0;
            }
        }
        else {
            fprintf(stderr,"%s: chdir: cannot find HOME in environment\n",programName);
            return 0;
        }
    }
    else if (directory[0] == '~') {
        /* substitute home directory path for '~' character */
        size_t len;
        char* buf;
        if (home == NULL) {
            fprintf(stderr,"%s: chdir: cannot find HOME in environment\n",programName);
            return 0;
        }
        len = strlen(home);
        buf = malloc(len + strlen(directory+1));
        strcpy(buf,home);
        strcpy(buf+len,directory+1);
        if (chdir(buf) == -1) {
            free(buf);
            fprintf(stderr,"%s: cd: '%s': %s\n",programName,buf,strerror(errno));
            return 0;
        }
        free(buf);
    }
    else if (chdir(directory) == -1) {
        fprintf(stderr,"%s: cd: '%s': %s\n",programName,directory,strerror(errno));
        return 0;
    }
    return 1;
}

/*int pud(const char* directory)
{
    return *cmdline;
}

int pod()
{
    return *cmdline;
    }*/

int readline(FILE* fin,char* buf,size_t cap)
{
    size_t s = --cap;
    while (cap > 0) {
        size_t len;
        if (fgets(buf,cap+1,fin) == NULL)
            return feof(fin) && cap<s;
        len = strlen(buf);
        if (buf[len-1] == '\n')
            break;
        buf += len;
        cap -= len;
    }
    return 1;
}
