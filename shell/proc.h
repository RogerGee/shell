/* proc.h */
#ifndef SHELL_PROC_H
#define SHELL_PROC_H
#include <sys/types.h>

/* utility types */

struct cmdargv
{
    char** argv;
    size_t argc, argcap;

    char* argbuf;
    size_t argbufHead, argbufcap;

    /* if false, then the command-line was incomplete */
    int state;
};
void cmdargv_init(struct cmdargv* argv);
int cmdargv_parse(struct cmdargv* argv,char* cmdline);
void cmdargv_reset(struct cmdargv* argv);
void cmdargv_delete(struct cmdargv* argv);

/* wraps the creation and management of a child process */
struct process
{
    /* information to create process; strings are stored by reference */
    int input, /* if -1, then inherit; else they are duped and closed */ 
        output, 
        error;
    const char* exec;
    char* const* argv;

    /* running process */
    pid_t pid;
    int exitCode;
};
struct process* process_new(const char* const argv[]); /* argv[n-1] is NULL */
void process_free(struct process* proc);
void process_init(struct process* proc,const char* const argv[]); /* argv[n-1] is NULL */
void process_assign_stdio(struct process* proc,int input,int output,int error);
int process_exec(struct process* proc);
int process_poll(struct process* proc); /* returns: 0 if exited, 1 if still running */
int process_wait(struct process* proc);
int process_wait_timeout(struct process* proc,unsigned int msecs); /* returns: 0 if exited, 1 if timed-out */
int process_signal(struct process* proc,int sig);
int process_kill(struct process* proc); /* send unconditional kill */
void process_delete(struct process* proc);

/* wraps the management of a job (pipeline); a job is one or more
   processes in their own process group */
struct job
{
    /* input to job; output from job; error from job:
        if these are -1, then input/output is inherited; otherwise
       they are duped; they handles are not closed until the job
       is deleted so that they are available to the user */
    int input, output, error;

    /* process information */
    struct process* procs;
    size_t procc, proccap;

    /* command-line buffers */
    char* cmdline;
};
struct job* job_new(int commc,const char* const* argv[]); /* use command-line in vector form, already parsed */
struct job* job_new_ex(const char* cmdline); /* parse command-line */
void job_free(struct job* pline);
void job_init(struct job* pline,int commc,const char* const* argv[]);
void job_init_ex(struct job* pline,const char* cmdline);
void job_assign_stdio(struct job* pline,int input,int output,int error);
int job_exec(struct process* proc);
int job_poll(struct job* pline);
int job_wait(struct job* pline);
int job_wait_timeout(struct job* pline,unsigned int msecs);
int job_kill(struct job* pline);
void job_delete(struct job* pline);

#endif
