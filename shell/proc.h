/* proc.h */
#ifndef SHELL_PROC_H
#define SHELL_PROC_H
#include <sys/types.h>

#define PROC_UNDEFINED (int)0xefffffffL

/* cmdargv: handles command-line parsing; this is for reading in the initial command-line;
   further processing (such as through job_argv_buffer functionality) is still required */
struct cmdargv;
struct cmdargv* cmdargv_new();
void cmdargv_free(struct cmdargv* argv);
int cmdargv_parse(struct cmdargv* argv,const char* cmdline);
const char* const* cmdargv_get_argv(struct cmdargv* argv);
void cmdargv_reset(struct cmdargv* argv);

/* process: wraps the creation and management of a child process */
struct process;
struct process_exit_info
{
    int exitCode;
    int exitSignal;
};
struct process* process_new(const char* const argv[]); /* argv[n-1] is NULL */
void process_free(struct process* proc);
void process_assign_stdio(struct process* proc,int input,int output,int error);
int process_exec(struct process* proc); /* returns -1 on failure; 0 is started successfully */
int process_poll(struct process* proc); /* returns: 0 if exited, 1 if still running; -1 if no more children */
int process_wait(struct process* proc);
int process_wait_timeout(struct process* proc,unsigned int msecs); /* returns: 0 if exited, 1 if timed-out */
int process_signal(struct process* proc,int sig);
int process_kill(struct process* proc); /* send unconditional kill */
struct process_exit_info* process_get_exit_info(struct process* proc);

/* job_argv_buffer: handles command-line argument parsing and allocation for jobs */
struct job_argv_buffer;
struct job_argv_buffer* job_argv_buffer_new();
void job_argv_buffer_free(struct job_argv_buffer* buf);
int job_argv_buffer_transform(struct job_argv_buffer* buf,struct cmdargv* argv);
void job_argv_buffer_reset(struct job_argv_buffer* buf);

/* wraps the management of a job (pipeline); a job is one or more
   processes in their own process group */
struct job;
struct job* job_new(struct job_argv_buffer* buffer); /* use command-line stored in job_argv_buffer; apply redirections */
struct job* job_new_ex(const char* cmdline); /* parse command-line; do not apply redirections */
void job_free(struct job* job);
int job_error_flag(struct job* job);
pid_t job_process_group(struct job* job);
struct process* job_get_proc(struct job* job,size_t index); /* if index is out of range, NULL is returned */
void job_assign_stdio(struct job* job,int input,int output,int error); /* this will overwrite any previous redirections */
int job_exec(struct job* job);
int job_poll(struct job* job);
int job_wait(struct job* job);
int job_wait_timeout(struct job* job,unsigned int msecs);
int job_signal(struct job* job,int sig);
int job_kill(struct job* job);

#endif
