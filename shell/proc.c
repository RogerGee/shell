/* proc.c */
#include "proc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

extern const char* programName;
extern void raise_exception(const char* message);

/* utility types */

/* cmdargv */
void cmdargv_init(struct cmdargv* argv)
{
    argv->argc = 0;
    argv->argcap = 8;
    argv->argv = malloc(argv->argcap * sizeof(char*));
    argv->argv[0] = NULL;
    argv->argbufcap = 4096;
    argv->argbuf = malloc(argv->argbufcap);
    argv->argbufHead = 0;
    argv->state = 1;
}
static int cmdargv_check_resize_argv(struct cmdargv* argv)
{
    if (argv->argc >= argv->argcap) {
        void* newbuf;
        size_t newcap, i;
        newcap = argv->argcap << 1;
        newbuf = realloc(argv->argv,newcap * sizeof(char*));
        if (newbuf == NULL) {
            argv->argv[argv->argc-1] = NULL;
            return 0;
        }
        argv->argv = newbuf;
        argv->argcap = newcap;
    }
    return 1;
}
int cmdargv_parse(struct cmdargv* argv,char* cmdline)
{
    /* parses the command-line string into an argument vector; the
       command-line should be terminated with a '\n' character */
    int last;
    size_t i, len;
    len = strlen(cmdline);
    /* ensure enough space in buffer for command-line; in practice it might
       take less than 'len' number of bytes since some characters are stripped out */
    if (1+len+argv->argbufHead > argv->argbufcap) {
        void* newbuf;
        size_t newcap;
        newcap = argv->argbufcap << 1;
        newbuf = realloc(argv->argbuf,newcap);
        if (newbuf == NULL)
            len = argv->argbufcap - argv->argbufHead;
        else {
            argv->argbuf = newbuf;
            argv->argcap = newcap;
        }
    }
    i = 0;
    while (i < len) {
        if (argv->state == 1) {
            /* state1: no argument found yet */
            if ( !isspace(cmdline[i]) ) {
                if (cmdline[i] == '"') {
                    ++i;
                    argv->state = 3;
                    if (i >= len)
                        /* incomplete */
                        return 0;
                }
                else
                    argv->state = 2;
                /* ensure arg buffer has sufficient capacity */
                if ( !cmdargv_check_resize_argv(argv) )
                    /*  we ran out of memory; I don't want to raise an exception
                        here, but this will cause undefined behavior (but is still safe) */
                    return 1;
                /* begin new argument */
                argv->argv[argv->argc++] = argv->argbuf + argv->argbufHead;
                continue;
            }
        }
        else if (argv->state == 2) {
            /* state2: non-quoted argument */
            last = cmdline[i];
            if (last == '\\') {
                ++i;
                if (i+1 >= len)
                    /* incomplete (quit now so that newline is NOT included in
                       the argument; this is a nice behavior for line continuation; bash does it) */
                    return 0;
            }
            if (last!='\\' && isspace(cmdline[i])) {
                /* complete the argument and start the process again (state1) */
                argv->argbuf[argv->argbufHead++] = 0;
                argv->state = 1;
            }
            else
                argv->argbuf[argv->argbufHead++] = cmdline[i];
        }
        else if (argv->state == 3) {
            /* state3: quoted argument */
            last = cmdline[i];
            if (last == '\\') {
                ++i;
                if (i+1 >= len)
                    /* incomplete */
                    return 0;
            }
            if (last!='\\' && cmdline[i]=='"') {
                argv->argbuf[argv->argbufHead++] = 0;
                argv->state = 1;
            }
            else {
                argv->argbuf[argv->argbufHead++] = cmdline[i];
                if (i+1 >= len)
                    /* incomplete */
                    return 0;
            }
        }
        ++i;
    }
    /* add NULL ptr to terminate list after checking for enough capacity */
    cmdargv_check_resize_argv(argv);
    argv->argv[argv->argc] = NULL;
    return 1;
}
void cmdargv_reset(struct cmdargv* argv)
{
    argv->argc = 0;
    argv->argv[0] = NULL;
    argv->argbufHead = 0;
    argv->argbuf[0] = 0;
    argv->state = 1;
}
void cmdargv_delete(struct cmdargv* argv)
{
    free(argv->argv);
    free(argv->argbuf);
}

/* process */
struct process* process_new(const char* const argv[])
{
    struct process* proc;
    proc = malloc(sizeof(struct process));
    process_init(proc,argv);
    return proc;
}
void process_free(struct process* proc)
{
    process_delete(proc);
    free(proc);
}
void process_init(struct process* proc,const char* const argv[])
{
    proc->input = proc->output = proc->error = -1;
    proc->exec = argv[0];
    proc->argv = (char* const*)argv;
    proc->pid = (pid_t)-1;
    proc->exitCode = -1;
}
void process_assign_stdio(struct process* proc,int input,int output,int error)
{
    if (proc->pid != (pid_t)-1) {
        proc->input = input;
        proc->output = output;
        proc->error = error;
    }
}
int process_exec(struct process* proc)
{
    if (proc->pid == (pid_t)-1) {
        proc->pid = fork();
        if (proc->pid == -1)
            raise_exception("fail fork()");
        if (proc->pid == 0) {
            /* if specified, redirect the standard file descriptors
               for this new process */
            if (proc->input != -1) {
                if (dup2(proc->input,STDIN_FILENO) != STDIN_FILENO)
                    raise_exception("fail dup2()");
                close(proc->input);
            }
            if (proc->output != -1) {
                if (dup2(proc->output,STDOUT_FILENO) != STDOUT_FILENO)
                    raise_exception("fail dup2()");
                close(proc->output);
            }
            if (proc->error != -1) {
                if (dup2(proc->error,STDERR_FILENO) != STDERR_FILENO)
                    raise_exception("fail dup2()");
                close(proc->error);
            }
            /* try to execute the command */
            execvp(proc->exec,proc->argv);
            /* command could not be executed */
            fprintf(stderr,"%s: No command '%s' found\n",programName,proc->exec);
            exit(-1);
        }
        else {
            /* close descriptors that were (hopefully) duped in the child */
            if (proc->input != -1)
                close(proc->input);
            if (proc->output != -1)
                close(proc->output);
            if (proc->error != -1)
                close(proc->error);
            proc->input = proc->output = proc->error = -1;
        }
    }
    return -1;
}
int process_poll(struct process* proc)
{
    if (proc->pid != (pid_t)-1) {
        pid_t r;
        int status;
        r = waitpid(proc->pid,&status,WNOHANG);
        if (r == -1) {
            if (errno == ECHILD) {
                proc->pid = -1;
                return -1;
            }
            raise_exception("fail waitpid()");
        }
        if (r == 0)
            /* child process terminated */
            return 0;
        /* child process is still running */
        return 1;
    }
    return -1;
}
int process_wait(struct process* proc)
{
    /* wait indefinitely on the child process */
    if (proc->pid != (pid_t)-1) {
        int status;
        if (waitpid(proc->pid,&status,0) != proc->pid) {
            if (errno == ECHILD) {
                proc->pid = (pid_t)-1;
                return -1;
            }
            raise_exception("fail waitpid()");
        }
        proc->pid = (pid_t)-1;
        proc->exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return 0;
    }
    return -1;
}
int process_wait_timeout(struct process* proc,unsigned int msecs)
{
    while (msecs > 0) {
        pid_t r;
        int status;
        r = waitpid(proc->pid,&status,WNOHANG);
        if (r == -1) {
            if (errno == ECHILD) {
                proc->pid = (pid_t)-1;
                return -1;
            }
            raise_exception("fail waitpid()");
        }
        if (r == proc->pid) {
            proc->pid = (pid_t)-1;
            proc->exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            /* process exited */
            return 0;
        }
        /* wait in intervals of 1000 microseconds to achieve milliseconds */
        usleep(1000);
        msecs -= 1;
    }
    /* process still alive (at point of last poll) */
    return 1;
}
int process_signal(struct process* proc,int sig)
{
    if (proc->pid != (pid_t)-1) {
        if (kill(proc->pid,sig) == -1)
            raise_exception("fail kill()");
        return 0;
    }
    return -1;
}
int process_kill(struct process* proc)
{
    /* do an unconditional kill to terminate the process */
    if (proc->pid != (pid_t)-1) {
        if (kill(proc->pid,SIGKILL) == -1)
            raise_exception("fail kill()");
        return 0;
    }
    return -1;
}
void process_delete(struct process* proc)
{
    process_kill(proc);
    process_wait(proc);
    proc->exec = NULL;
    proc->argv = NULL;
}
