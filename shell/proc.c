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
#include <sys/fcntl.h>
#include <fcntl.h>

extern const char* programName;
extern void raise_exception(const char* message);

/* utility types */

/* cmdargv */
struct cmdargv
{
    char** argv;
    size_t argc, argcap;

    char* argbuf;
    size_t argbufHead, argbufcap;

    /* if false, then the command-line was incomplete */
    int state;
};
static void cmdargv_init(struct cmdargv* argv)
{
    argv->argc = 0;
    argv->argcap = 8;
    argv->argv = malloc(argv->argcap * sizeof(char*));
    if (argv->argv == NULL)
        raise_exception("out of memory");
    argv->argv[0] = NULL;
    argv->argbufcap = 4096;
    argv->argbuf = malloc(argv->argbufcap);
    if (argv->argbuf == NULL)
        raise_exception("out of memory");
    argv->argbufHead = 0;
    argv->state = 1;
}
static void cmdargv_delete(struct cmdargv* argv)
{
    free(argv->argv);
    free(argv->argbuf);
}
struct cmdargv* cmdargv_new()
{
    struct cmdargv* argv;
    argv = malloc(sizeof(struct cmdargv));
    if (argv == NULL)
        raise_exception("out of memory");
    cmdargv_init(argv);
    return argv;
}
void cmdargv_free(struct cmdargv* argv)
{
    cmdargv_delete(argv);
    free(argv);
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
int cmdargv_parse(struct cmdargv* argv,const char* cmdline)
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
const char* const* cmdargv_get_argv(struct cmdargv* argv)
{
    return (const char* const*)argv->argv;
}
void cmdargv_reset(struct cmdargv* argv)
{
    argv->argc = 0;
    argv->argv[0] = NULL;
    argv->argbufHead = 0;
    argv->argbuf[0] = 0;
    argv->state = 1;
}

/* process */
struct process
{
    /* information to create process; strings are stored by reference */
    int input, /* if -1, then inherit; else they are duped and closed */ 
        output,
        error;
    const char* exec;
    char* const* argv;

    /* running process */
    pid_t pid, pgid;
    int exitCode;
};
static void process_init(struct process* proc,const char* const argv[])
{
    proc->input = proc->output = proc->error = -1;
    proc->exec = argv[0];
    proc->argv = (char* const*)argv;
    proc->pid = (pid_t)-1;
    proc->pgid = (pid_t)-1;
    proc->exitCode = -1;
}
static void process_delete(struct process* proc)
{
    process_kill(proc);
    process_wait(proc);
    proc->exec = NULL;
    proc->argv = NULL;
}
struct process* process_new(const char* const argv[])
{
    struct process* proc;
    proc = malloc(sizeof(struct process));
    if (proc == NULL)
        raise_exception("out of memory");
    process_init(proc,argv);
    return proc;
}
void process_free(struct process* proc)
{
    process_delete(proc);
    free(proc);
}
void process_assign_stdio(struct process* proc,int input,int output,int error)
{
    proc->input = input;
    proc->output = output;
    proc->error = error;
}
int process_exec(struct process* proc)
{
    if (proc->pid == (pid_t)-1) {
        proc->pid = fork();
        if (proc->pid == -1)
            raise_exception("fail fork()");
        if (proc->pid == 0) {
            int fd;
            /* if specified, set the process in the specified process group */
            if (proc->pgid!=-1 && setpgid(0,proc->pgid)==-1)
                raise_exception("fail setpgid()\n");
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
            exit(EXIT_FAILURE);
        }
        else { /* parent */
            /* close descriptors that were (hopefully) duped in the child */
            if (proc->input != -1)
                close(proc->input);
            if (proc->output != -1)
                close(proc->output);
            if (proc->error != -1)
                close(proc->error);
            proc->input = proc->output = proc->error = -1;
        }
        return 0;
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

/* job_argv */
struct dyninfo {
    size_t head;
    size_t capc;
    const char** argv;
};
static void dyninfo_init(struct dyninfo* info)
{
    info->argv = NULL;
    info->head = 0;
    info->capc = 0;
}
static int dyninfo_alloc(struct dyninfo* info)
{
    void* buf;
    size_t capc;
    capc = info->argv == NULL ? 8 : (info->capc << 1);
    buf = realloc(info->argv,sizeof(const char*) * capc);
    if (buf == NULL)
        return 0;
    info->argv = buf;
    info->capc = capc;
    return 1;
}
static void dyninfo_delete(struct dyninfo* info)
{
    free(info->argv);
    info->argv = NULL;
}
struct job_argv_buffer
{
    size_t head, capc;
    struct dyninfo* info; /* array info for each job command-line */
    const char* outFile, *outFileAppend;
    const char* inFile;
};
static void job_argv_buffer_init(struct job_argv_buffer* buf)
{
    size_t i;
    buf->head = 0;
    buf->capc = 8;
    buf->info = malloc(sizeof(struct dyninfo) * buf->capc);
    if (buf->info == NULL)
        raise_exception("out of memory");
    for (i = 0;i < buf->capc;++i)
        dyninfo_init(buf->info+i);
    buf->outFile = buf->outFileAppend = buf->inFile = NULL;
}
static void job_argv_buffer_delete(struct job_argv_buffer* buf)
{
    size_t i;
    for (i = 0;i < buf->capc;++i)
        dyninfo_delete(buf->info+i);
    free(buf->info);
}
struct job_argv_buffer* job_argv_buffer_new()
{
    struct job_argv_buffer* buf;
    buf = malloc(sizeof(struct job_argv_buffer));
    if (buf == NULL)
        raise_exception("out of memory");
    job_argv_buffer_init(buf);
    return buf;
}
void job_argv_buffer_free(struct job_argv_buffer* buf)
{
    job_argv_buffer_delete(buf);
    free(buf);
}
static int job_argv_buffer_append(struct job_argv_buffer* buf,size_t index,const char* arg)
{
    /* check if a new command needs to be added */
    struct dyninfo* ins;
    if (index >= buf->head) {
        if (buf->head >= buf->capc) {
            void* newbuf;
            size_t iter, newcapc;
            newcapc = buf->capc << 1;
            newbuf = realloc(buf->info,sizeof(struct dyninfo) * newcapc);
            if (newbuf == NULL)
                return 0;
            buf->info = newbuf;
            buf->capc = newcapc;
            for (iter = buf->head;iter < buf->capc;++iter)
                dyninfo_init(buf->info+iter);
        }
        ins = buf->info + buf->head;
        ++buf->head;
    }
    else
        ins = buf->info + index;
    if (ins->head>=ins->capc && !dyninfo_alloc(ins))
        return 0;
    ins->argv[ins->head++] = arg;
    return 1;
}
int job_argv_buffer_transform(struct job_argv_buffer* buf,struct cmdargv* argv)
{
    char s = 1;
    char* arg;
    size_t comdex = 0;
    char** v = argv->argv;
    arg = *v++;
    while (1) {
        if (arg == NULL) {
            if (!job_argv_buffer_append(buf,comdex,NULL))
                /* make sure that the buffer is null-terminated */
                buf->info[buf->head-1].argv[buf->info[buf->head-1].head-1] = NULL;
            break;
        }
        else if (arg[0] == '<') {
            /* < file syntax: job input comes from specified file */
            buf->inFile = arg[1] ? arg+1 : *v++;
            arg = *v++;
        }
        else if (arg[0] == '>') {
            /* > file (>> file) syntax; job output goes to file; >> is append mode */
            if (arg[1] == '>')
                buf->outFileAppend = arg[2] ? arg+2 : *v++;
            else
                buf->outFile = arg[1] ? arg+1 : *v++;
            arg = *v++;
        }
        else if (arg[0] == '|') {
            if (s == 0) {
                fprintf(stderr,"%s: syntax: unexpected '|' in command-line\n",programName);
                return 0;
            }
            /* add a null-ptr to the buffer to signal the end of the last command; then update
               comdex so that it will create a new command next time */
            if (!job_argv_buffer_append(buf,comdex,NULL)) {
                /* make sure that the buffer is null-terminated */
                buf->info[buf->head-1].argv[buf->info[buf->head-1].head-1] = NULL;
                break;
            }
            arg = arg[1] ? arg+1 : *v++;
            ++comdex;
            s = 0;
        }
        else {
            if (!job_argv_buffer_append(buf,comdex,arg)) {
                /* make sure that the buffer is null-terminated */
                buf->info[buf->head-1].argv[buf->info[buf->head-1].head-1] = NULL;
                break;
            }
            arg = *v++;
            s = 1;
        }
    }
    if (s == 0) {
        fprintf(stderr,"%s: syntax: expected command name after '|'\n",programName);
        return 0;
    }
    return 1;
}
void job_argv_buffer_reset(struct job_argv_buffer* buf)
{
    size_t iter;
    for (iter = 0;iter < buf->head;++iter)
        buf->info[iter].head = 0;
    buf->head = 0;
    buf->outFile = buf->outFileAppend = buf->inFile = NULL;
}

/* job */
struct job
{
    /* bitmask:
        bit0: errorflag
        bit1: is job_ex */
    short flags;

    /* input to job; output from job; error from job:
        if these are -1, then input/output is inherited; otherwise
       they are duped; the job functionality is NOT responsible for
       closing these descriptors; the process functionality will
       close them so that they don't exist in the parent process */
    int input, output, error;

    /* process information */
    struct process* procs;
    size_t proccnt;
    pid_t pgid; /* process group id */
};
/* this subclass stores an internal argument buffer */
struct job_ex
{
    struct job _base;

    /* command-line argument buffers */
    struct cmdargv argv;
    struct job_argv_buffer buf;
};

static void job_init(struct job* job,struct job_argv_buffer* buffer)
{
    int p[2];
    size_t iter;
    job->proccnt = buffer->head;
    job->procs = malloc(sizeof(struct process) * job->proccnt);
    job->pgid = (pid_t)-1;
    job->flags = 0;
    if (buffer->outFile != NULL) {
        job->output = open(buffer->outFile,O_WRONLY|O_CREAT|O_TRUNC,0666);
        if (job->output == -1) {
            fprintf(stderr,"%s: cannot open file '%s' for writing: %s\n",programName,buffer->outFile,strerror(errno));
            job->flags |= 1;
            return;
        }
    }
    else if (buffer->outFileAppend != NULL) {
        job->output = open(buffer->outFileAppend,O_WRONLY|O_CREAT|O_APPEND,0666);
        if (job->output == -1) {
            fprintf(stderr,"%s: cannot open file '%s' for append: %s\n",programName,buffer->outFileAppend,strerror(errno));
            job->flags |= 1;
            return;
        }
    }
    else
        job->output = -1;
    if (buffer->inFile != NULL) {
        job->input = open(buffer->inFile,O_RDONLY);
        if (job->input == -1) {
            fprintf(stderr,"%s: cannot open file '%s' for reading: %s\n",programName,buffer->inFile,strerror(errno));
            job->flags |= 1;
            return;
        }
    }
    else
        job->input = -1;
    job->error = -1;
    for (iter = 0;iter < job->proccnt;++iter) {
        int fds[3] = {-1,-1,-1};
        process_init(job->procs+iter,(buffer->info+iter)->argv);
        /* apply redirections; link up processes with pipe object */
        if (iter > 0)
            /* assign read end of pipe as input to process; this was
               left over from a previous iteration */
            fds[0] = p[0];
        if (job->proccnt>1 && iter+1<job->proccnt) {
            /* create pipe; use its write end for the output of
               the current process; save its read end for input
               of the next process */
            if (pipe(p) == -1)
                raise_exception("system call pipe() failed");
            if (fcntl(p[0],F_SETFD,FD_CLOEXEC)==-1 || fcntl(p[1],F_SETFD,FD_CLOEXEC)==-1)
                raise_exception("system call fcntl() failed");
            fds[1] = p[1];
        }
        if (iter==0 && job->input!=-1)
            /* file as input to first job process */
            fds[0] = job->input;
        else if (iter+1 == job->proccnt) {
            if (job->output != -1)
                /* file as output from final job process */
                fds[1] = job->output;
            if (job->error != -1)
                /* file as error output from final job process */
                fds[2] = job->error;
        }
        process_assign_stdio(job->procs+iter,fds[0],fds[1],fds[2]);
    }
}
static void job_init_ex(struct job_ex* job,const char* cmdline)
{
    /* this variant is similar except we do not apply redirections
       for the job's input and output; they are silently ignored */
    int p[2];
    size_t iter;
    cmdargv_init(&job->argv);
    if ( !cmdargv_parse(&job->argv,cmdline) )
        raise_exception("syntax error in command-line on job creation: fail cmdargv_parse()");
    job_argv_buffer_init(&job->buf);
    if ( !job_argv_buffer_transform(&job->buf,&job->argv) )
        raise_exception("syntax error in command-line on job creation: fail job_argv_buffer_transform");
    /* ignore redirections */
    job->buf.outFile = job->buf.outFileAppend = job->buf.inFile = NULL;
    job_init(&job->_base,&job->buf); /* call base-class constructor */
    job->_base.flags |= 2; /* set subclass bit to true */
}
static void job_delete(struct job* job)
{
    job_kill(job);
    job_wait(job);
    /* note: a 'struct process' does not allocate anything; it does not need to be destroyed;
       this is convinient since we just use them to wrap execution, not*/
    free(job->procs);
    if (job->flags & 2) {
        job_argv_buffer_delete(&((struct job_ex*)job)->buf);
        cmdargv_delete(&((struct job_ex*)job)->argv);
    }
}
struct job* job_new(struct job_argv_buffer* buffer)
{
    struct job* job;
    job = malloc(sizeof(struct job));
    if (job == NULL)
        raise_exception("out of memory");
    job_init(job,buffer);
    return job;
}
struct job* job_new_ex(const char* cmdline)
{
    struct job_ex* job;
    job = malloc(sizeof(struct job_ex));
    if (job == NULL)
        raise_exception("out of memory");
    job_init_ex(job,cmdline);
    return (struct job*)job;
}
void job_free(struct job* job)
{
    job_delete(job);
    free(job);
}
int job_error_flag(struct job* job)
{
    /* see if bit0 is set (binary 1) */
    return job->flags & 0x01;
}
pid_t job_process_group(struct job* job)
{
    return job->pgid;
}
void job_assign_stdio(struct job* job,int input,int output,int error)
{
    if (job->proccnt > 0) {
        if (job->input != -1)
            close(job->input);
        job->input = input;
        job->procs[0].input = input;
        if (job->output != -1)
            close(job->output);
        job->output = output;
        job->procs[job->proccnt-1].output = output;
        if (job->error != -1)
            close(job->error);
        job->error = error;
        job->procs[job->proccnt-1].error = error;
    }
}
int job_exec(struct job* job)
{
    if (job->pgid==-1 && job->proccnt>0) {
        size_t i;
        /* tell the first process to set its gid
           to itself (create a new process group) */
        job->procs[0].pgid = 0;
        if (process_exec(job->procs) == -1)
            return -1;
        job->pgid = job->procs[0].pid;
        /* set process group to prevent race conditions */
        if (setpgid(job->procs[0].pid,job->pgid)==-1 && errno!=EACCES)
            raise_exception("fail setpgid()");
        /* execute remaining processes in pipeline */
        for (i = 1;i < job->proccnt;++i) {
            job->procs[i].pgid = job->pgid; /* set process group flag */
            if (process_exec(job->procs+i) == -1)
                /* fail - user should call job_delete */
                return -1;
            if (setpgid(job->procs[i].pid,job->pgid)==-1 && errno!=EACCES)
                raise_exception("fail setpgid()");
        }
        return 0;
    }
    return -1;
}
/*int job_poll(struct job* job)
{
}*/
int job_wait(struct job* job)
{
    if (job->pgid != (pid_t)-1) {
        while (1) {
            size_t i;
            pid_t pid;
            int status;
            if ((pid = waitpid(-job->pgid,&status,0)) == -1) {
                if (errno == ECHILD) {
                    job->pgid = (pid_t)-1;
                    return 0;
                }
                raise_exception("fail waitpid()");
            }
            /* search for process structure to assign exit code */
            for (i = 0;i < job->proccnt;++i)
                if (job->procs[i].pid == pid)
                    job->procs[i].exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        return 0;
    }
    return -1;
}/*
int job_wait_timeout(struct job* job,unsigned int msecs)
{
}*/
int job_signal(struct job* job,int sig)
{
    if (job->pgid != (pid_t)-1) {
        if (kill(-job->pgid,sig) == -1)
            raise_exception("fail kill()");
        return 0;
    }
    return -1;
}
int job_kill(struct job* job)
{
    if (job->pgid != (pid_t)-1) {
        if (kill(-job->pgid,SIGKILL) == -1)
            raise_exception("fail kill()");
        return 0;
    }
    return -1;
}
