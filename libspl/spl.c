#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "spl.h"


/*  */
typedef struct 
{
    const char* name;
    const int (*stub)(scmp_filter_ctx);
} pledge_t;

#define ALLOW(syscall_name) ({ int ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syscall_name), 0); if (ret != 0) { return ret; }})

#define ERROR_OUT_RET(ret) ({ int r = (ret); if (r != 0) { return r; }})

#define RET_WITH_ERR(err) \
    errno = (err); \
    return -1; 



int _stdio_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(close);
	ALLOW(dup);
	ALLOW(dup2);
	ALLOW(dup3);
	ALLOW(write);
	ALLOW(pwrite64);
	ALLOW(read);
	ALLOW(preadv);
	ALLOW(pread64);
	ALLOW(preadv);
	ALLOW(lseek);
	ALLOW(sendmsg);
	ALLOW(recvmsg);
	ALLOW(recvfrom);
	ALLOW(poll);
	ALLOW(select);
	ALLOW(sync);
	ALLOW(fcntl);
	ALLOW(ftruncate);
	ALLOW(fchdir);
	ALLOW(fstat);
	ALLOW(fsync);
	ALLOW(vhangup);
	ALLOW(fcntl64);
	ALLOW(fstat64);
	ALLOW(epoll_create);
	ALLOW(epoll_create1);
	ALLOW(epoll_ctl);
	ALLOW(epoll_ctl_old);
	ALLOW(epoll_pwait);
	ALLOW(epoll_wait);
	ALLOW(epoll_wait_old);
	ALLOW(fadvise64);
	ALLOW(fchdir);
	ALLOW(_sysctl);
	ALLOW(rt_sigaction);
	ALLOW(rt_sigprocmask);
	ALLOW(rt_sigpending);
	ALLOW(rt_sigqueueinfo);
	ALLOW(rt_sigtimedwait);
	ALLOW(rt_sigsuspend);
	ALLOW(rt_sigreturn);
	ALLOW(rt_tgsigqueueinfo);
	ALLOW(sigaltstack);
	ALLOW(signalfd);
	ALLOW(signalfd4);
	ALLOW(eventfd);
	ALLOW(eventfd2);
	ALLOW(restart_syscall);
	ALLOW(time);
	ALLOW(settimeofday);
	ALLOW(gettimeofday);
	ALLOW(clock_gettime);
	ALLOW(clock_getres);
	ALLOW(clock_adjtime);
	ALLOW(clock_nanosleep);
	ALLOW(timer_create);
	ALLOW(timer_delete);
	ALLOW(timer_settime);
	ALLOW(timer_gettime);
	ALLOW(timer_getoverrun);
	ALLOW(alarm);
	ALLOW(setitimer);
	ALLOW(getitimer);
	ALLOW(ftime);
	ALLOW(timerfd_create);
	ALLOW(timerfd_gettime);
	ALLOW(timerfd_settime);
	ALLOW(sched_yield);
	ALLOW(getpriority);
	ALLOW(getpid);
	ALLOW(getppid);
	ALLOW(gettid);
	ALLOW(getresgid);
	ALLOW(geteuid);
	ALLOW(getegid);
	ALLOW(getgroups);
	ALLOW(getresuid);
	ALLOW(getgid);
	ALLOW(getuid);
	ALLOW(getpgid);
	ALLOW(getpgrp);
	ALLOW(getsid);
	ALLOW(madvise);
	ALLOW(mmap);
	ALLOW(munmap);
	ALLOW(mremap);
	ALLOW(msync);
	ALLOW(brk);
	ALLOW(mlock);
	ALLOW(mlock2);
	ALLOW(mlockall);
	ALLOW(munlock);
	ALLOW(munlockall);
	ALLOW(membarrier);
	ALLOW(modify_ldt);
	ALLOW(fallocate);
	ALLOW(fanotify_init);
	ALLOW(fanotify_mark);
	ALLOW(futex);
	ALLOW(write);
	ALLOW(writev);
	ALLOW(inotify_add_watch);
	ALLOW(inotify_init);
	ALLOW(inotify_init1);
	ALLOW(inotify_rm_watch);
	ALLOW(io_cancel);
	ALLOW(io_destroy);
	ALLOW(io_getevents);
	ALLOW(io_setup);
	ALLOW(io_submit);
	ALLOW(getrandom);
	ALLOW(lseek);
	ALLOW(pkey_alloc);
	ALLOW(pkey_free);
	ALLOW(pkey_mprotect);
	ALLOW(getrlimit);
	ALLOW(poll);
	ALLOW(ppoll);
	ALLOW(ioctl);
	ALLOW(nanosleep);
	ALLOW(stat);
	ALLOW(pselect6);
	ALLOW(signalfd);
	ALLOW(signalfd4);
	ALLOW(shutdown);
	ALLOW(pread64);
	ALLOW(preadv);
	ALLOW(preadv2);
	ALLOW(read);
	ALLOW(readv);
	ALLOW(readlink);
	ALLOW(umask);
	ALLOW(pipe);
	ALLOW(pipe2);
	ALLOW(pause);
	ALLOW(wait4);
	ALLOW(getgroups);
	ALLOW(memfd_create);
	ALLOW(msync);
	ALLOW(fdatasync);
	ALLOW(syncfs);
	ALLOW(getitimer);
	ALLOW(setitimer);
	ALLOW(times);
	ALLOW(get_robust_list);
	ALLOW(set_robust_list);
	ALLOW(get_thread_area);
	ALLOW(readahead);
	ALLOW(sync_file_range);
	ALLOW(remap_file_pages);
	ALLOW(recvmmsg);
	ALLOW(sendmmsg);
	ALLOW(sendfile);


	/* complex rules */

	/* sendto, sendmsg (restricted) */
	/* kill */
	/* waitid */

    return 0;
}


int _flock_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(flock);
	ALLOW(fcntl);


	/* complex rules */

    return 0;
}


int _resource_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(setrlimit);
	ALLOW(getrlimit);
	ALLOW(prlimit64);
	ALLOW(getrusage);
	ALLOW(acct);
	ALLOW(quotactl);
	ALLOW(ustat);
	ALLOW(statfs);
	ALLOW(fstatfs);
	ALLOW(sysfs);
	ALLOW(uname);
	ALLOW(sysinfo);
	ALLOW(perf_event_open);
	ALLOW(fstatfs64);
	//ALLOW(fstatat);
	ALLOW(getcpu);
	ALLOW(uname);


	/* complex rules */

    return 0;
}


int _proc_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(clone);
	ALLOW(fork);
	ALLOW(vfork);
	ALLOW(exit);
	ALLOW(wait4);
	ALLOW(waitid);
	ALLOW(getpid);
	ALLOW(getppid);
	ALLOW(gettid);
	ALLOW(getsid);
	ALLOW(getpgid);
	ALLOW(getpgrp);
	ALLOW(getuid);
	ALLOW(getgid);
	ALLOW(getresuid);
	ALLOW(getresgid);
	ALLOW(geteuid);
	ALLOW(getegid);
	ALLOW(getgroups);
	ALLOW(ptrace);
	ALLOW(prctl);
	ALLOW(uselib);
	ALLOW(process_vm_readv);
	ALLOW(process_vm_writev);
	ALLOW(kcmp);
	ALLOW(unshare);
	ALLOW(kill);
	ALLOW(tkill);
	ALLOW(tgkill);
	ALLOW(pause);
	ALLOW(sched_get_priority_max);
	ALLOW(sched_get_priority_min);
	ALLOW(sched_getaffinity);
	ALLOW(sched_getattr);
	ALLOW(sched_getparam);
	ALLOW(sched_getscheduler);
	ALLOW(sched_rr_get_interval);
	ALLOW(sched_setaffinity);
	ALLOW(sched_setattr);
	ALLOW(sched_setparam);
	ALLOW(sched_setscheduler);
	ALLOW(sched_yield);
	ALLOW(ioprio_set);
	ALLOW(ioprio_get);
	ALLOW(waitid);
	ALLOW(move_pages);
	ALLOW(migrate_pages);
	ALLOW(set_thread_area);
	ALLOW(unshare);


	/* complex rules */

    return 0;
}


int _exec_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(execve);
	ALLOW(execveat);

    /* TODO: explain why */
	ALLOW(mprotect);
    ALLOW(arch_prctl);
	ALLOW(prctl);

	/* complex rules */

    return 0;
}


int _thread_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(set_thread_area);
	ALLOW(get_thread_area);
	ALLOW(set_tid_address);
	ALLOW(arch_prctl);
	ALLOW(clone);
	ALLOW(fork);
	ALLOW(set_tid_address);

	/* complex rules */
	ERROR_OUT_RET(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0)));


    return 0;
}


int _memory_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(madvise);
	ALLOW(mprotect);
	ALLOW(mmap);
	ALLOW(munmap);
	ALLOW(mremap);
	ALLOW(msync);
	ALLOW(brk);
	ALLOW(mlock);
	ALLOW(mlock2);
	ALLOW(mlockall);
	ALLOW(munlock);
	ALLOW(munlockall);
	ALLOW(mincore);
	ALLOW(membarrier);
	ALLOW(modify_ldt);
	ALLOW(remap_file_pages);
	//ALLOW(sync_file_pages);


	/* complex rules */

    return 0;
}


int _rpath_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(chdir);
	ALLOW(access);
	ALLOW(faccessat);
	ALLOW(getcwd);
	ALLOW(getdents);
	ALLOW(getdents64);
	ALLOW(lstat);
	ALLOW(readlinkat);
	ALLOW(newfstatat);
	

	/* complex rules */
	//ERROR_OUT_RET(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, 0x3, O_RDONLY)));
	//ERROR_OUT_RET(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, 0x3, O_RDONLY)));

    return 0;
}


int _wpath_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(chmod);
	ALLOW(fchmod);
	ALLOW(fchmodat);
	ALLOW(creat);
	ALLOW(faccessat);
	ALLOW(getcwd);
	ALLOW(lstat);
	ALLOW(openat);
	ALLOW(readlinkat);
	ALLOW(truncate);


	/* complex rules */
	//ERROR_OUT_RET(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, 0x3, O_WRONLY)));
	//ERROR_OUT_RET(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, 0x3, O_WRONLY)));

    return 0;
}

int _rwpath_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(chmod);
	ALLOW(fchmod);
	ALLOW(fchmodat);
	ALLOW(creat);
	ALLOW(faccessat);
	ALLOW(getcwd);
	ALLOW(lstat);
	ALLOW(readlinkat);
	ALLOW(truncate);
	ALLOW(name_to_handle_at);
	ALLOW(open_by_handle_at);
	ALLOW(open);
	ALLOW(openat);

	/* complex rules */

	return 0;
}

int _cpath_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(mkdir);
	ALLOW(mkdirat);
	ALLOW(rename);
	ALLOW(renameat);
	ALLOW(renameat2);
	ALLOW(rmdir);
	ALLOW(symlink);
	ALLOW(symlinkat);
	ALLOW(unlink);
	ALLOW(unlinkat);
	ALLOW(link);
	ALLOW(linkat);


	/* complex rules */

    return 0;
}


int _dpath_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(mknod);
	ALLOW(mknodat);
	ALLOW(ustat);


	/* complex rules */

    return 0;
}


int _fattr_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(futimesat);
	ALLOW(utimensat);
	ALLOW(utime);
	ALLOW(utimes);
	ALLOW(fgetxattr);
	ALLOW(flistxattr);
	ALLOW(fremovexattr);
	ALLOW(fsetxattr);
	ALLOW(getxattr);
	ALLOW(listxattr);
	ALLOW(llistxattr);
	ALLOW(lremovexattr);
	ALLOW(lsetxattr);
	ALLOW(removexattr);
	ALLOW(lgetxattr);
	ALLOW(statx);
	ALLOW(setxattr);


	/* complex rules */

    return 0;
}


int _chown_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(chown);
	ALLOW(fchown);
	ALLOW(fchownat);
	ALLOW(lchown);


	/* complex rules */

    return 0;
}


int _dns_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(sendto);


	/* complex rules */

    return 0;
}


int _inet_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(bind);
	ALLOW(connect);
	ALLOW(listen);
	ALLOW(accept);
	ALLOW(accept4);
	ALLOW(socketpair);
	ALLOW(setsockopt);
	ALLOW(getsockopt);
	ALLOW(getsockname);
	ALLOW(getpeername);
	ALLOW(shutdown);


	/* complex rules */

    /* only allow socket to access AF_INET */
    ERROR_OUT_RET(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_A0(SCMP_CMP_EQ, AF_INET)));

    return 0;
}


int _unix_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(bind);
	ALLOW(connect);
	ALLOW(listen);
	ALLOW(accept);
	ALLOW(accept4);
	ALLOW(socketpair);
	ALLOW(setsockopt);
	ALLOW(getsockopt);
	ALLOW(getsockname);
	ALLOW(getpeername);
	ALLOW(shutdown);


	/* complex rules */

    /* only allow socket to access AF_INET */
    ERROR_OUT_RET(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_A0(SCMP_CMP_EQ, AF_UNIX)));


    return 0;
}


int _socket_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
    ALLOW(socket);
	ALLOW(bind);
	ALLOW(connect);
	ALLOW(listen);
	ALLOW(accept);
	ALLOW(accept4);
	ALLOW(socketpair);
	ALLOW(setsockopt);
	ALLOW(getsockopt);
	ALLOW(getsockname);
	ALLOW(getpeername);
	ALLOW(shutdown);

	/* complex rules */

    return 0;
}


int _settime_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(settimeofday);
	ALLOW(adjtimex);
	ALLOW(clock_settime);


	/* complex rules */

    return 0;
}


int _id_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(getpriority);
	ALLOW(setpriority);
	ALLOW(capset);
	ALLOW(capget);
	ALLOW(setns);
	ALLOW(setpriority);
	ALLOW(getpriority);
	ALLOW(setgroups);
	ALLOW(setpgid);
	ALLOW(setuid);
	ALLOW(setgid);
	ALLOW(setresuid);
	ALLOW(setresgid);
	ALLOW(setreuid);
	ALLOW(setregid);
	ALLOW(setfsuid);
	ALLOW(setfsgid);
	ALLOW(acct);


	/* complex rules */

    return 0;
}


int _ipc_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(tee);
	ALLOW(splice);
	//ALLOW(vmsplit);
	ALLOW(shmget);
	ALLOW(shmctl);
	ALLOW(shmat);
	ALLOW(shmdt);
	ALLOW(semget);
	ALLOW(semctl);
	ALLOW(semop);
	ALLOW(semtimedop);
	ALLOW(msgget);
	ALLOW(msgctl);
	ALLOW(msgsnd);
	ALLOW(msgrcv);
	ALLOW(mq_open);
	ALLOW(mq_unlink);
	ALLOW(mq_getsetattr);
	ALLOW(mq_timedsend);
	ALLOW(mq_timedreceive);
	ALLOW(mq_notify);


	/* complex rules */

    return 0;
}


int _numa_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(getcpu);
	ALLOW(set_mempolicy);
	ALLOW(get_mempolicy);
	ALLOW(mbind);
	ALLOW(move_pages);
	ALLOW(migrate_pages);


	/* complex rules */

    return 0;
}


int _kernel_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(create_module);
	ALLOW(init_module);
	ALLOW(finit_module);
	ALLOW(delete_module);
	ALLOW(query_module);
	ALLOW(get_kernel_syms);
	ALLOW(pivot_root);
	ALLOW(swapon);
	ALLOW(swapoff);
	ALLOW(mount);
	ALLOW(umount2);
	ALLOW(nfsservctl);
	ALLOW(_sysctl);
	ALLOW(syslog);
	ALLOW(personality);
	ALLOW(reboot);
	ALLOW(kexec_load);
	ALLOW(kexec_file_load);
	ALLOW(ioperm);
	ALLOW(iopl);
	ALLOW(add_key);
	ALLOW(request_key);
	ALLOW(keyctl);
	ALLOW(copy_file_range);
	ALLOW(reboot);
	ALLOW(kexec_file_load);
	ALLOW(kexec_load);
	ALLOW(sethostname);
	ALLOW(userfaultfd);
	ALLOW(request_key);
	ALLOW(setdomainname);
	ALLOW(prctl);
	ALLOW(kcmp);
	ALLOW(arch_prctl);


	/* complex rules */

    return 0;
}


int _bpf_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(bpf);


	/* complex rules */

    return 0;
}


int _unsafe_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(chroot);
	ALLOW(umount2);
	ALLOW(mount);
	ALLOW(uselib);
	ALLOW(tuxcall);
	ALLOW(afs_syscall);
	ALLOW(vserver);
	ALLOW(getpmsg);
	ALLOW(putpmsg);
	ALLOW(security);


	/* complex rules */

    return 0;
}


int _always_stub(scmp_filter_ctx ctx)
{
	/* simple rules */
	ALLOW(exit);
	ALLOW(exit_group);
	ALLOW(seccomp);
	ALLOW(syslog);
    ALLOW(prctl);


	/* complex rules */


    return 0;
}





/* group table */
static const pledge_t pledge_table[] = 
{
	{"stdio", _stdio_stub},
	{"flock", _flock_stub},
	{"resource", _resource_stub},
	{"proc", _proc_stub},
	{"exec", _exec_stub},
	{"thread", _thread_stub},
	{"memory", _memory_stub},
	{"rpath", _rpath_stub},
	{"wpath", _wpath_stub},
	{"rwpath", _rwpath_stub},
	{"cpath", _cpath_stub},
	{"dpath", _dpath_stub},
	{"fattr", _fattr_stub},
	{"chown", _chown_stub},
	{"dns", _dns_stub},
	{"inet", _inet_stub},
	{"unix", _unix_stub},
	{"socket", _socket_stub},
	{"settime", _settime_stub},
	{"id", _id_stub},
	{"ipc", _ipc_stub},
	{"numa", _numa_stub},
	{"kernel", _kernel_stub},
	{"bpf", _bpf_stub},
	{"unsafe", _unsafe_stub},
	{"always", _always_stub}
};




/* apply a pledge  */
static int apply_pledge(char* p, scmp_filter_ctx ctx)
{
    for(size_t i = 0; i < sizeof(pledge_table) / sizeof(pledge_t); i++)
    {
        const pledge_t* pledge = &pledge_table[i];

        /* match */
        if (strcmp(pledge->name, p) == 0)
        {
            return pledge->stub(ctx);
        }
    }

    errno = EINVAL;
    return -1;
}

/* pledge call implementation */
int pledge(const char* promises)
{
    
    int rc = -1;

    /* create a copy of promises */
    char* mpromises = strdup(promises);
    if (!mpromises)
    {
        RET_WITH_ERR(ENOMEM);
    }

    /* create a filter context */
    scmp_filter_ctx ctx = ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL)
    {
        goto out;
    }

    /* call stubs */    
    char* p = strtok(mpromises, " ");
    while(p)
    {
        rc = apply_pledge(p, ctx);
        if (rc != 0)
        {
            goto out;
        }

        p = strtok(NULL, " ");
    }

    /* always allowed syscalls */
    rc = apply_pledge("always", ctx);
    if (rc != 0) {
        goto out;
    }

    /* setup attrs */

    /* kill on bad arch -- done by default. */
    /*rc = seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL);
    if (rc != 0) {
        goto out;
    }*/

    /* set no new privs -- done by default. */
    /*rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 1);
    if (rc != 0) {
        goto out;
    }*/

    /* disable spectre mitigations and allow tsync */
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_SSB, 1);
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2);


	#if 0
        int fd = open("./curfilter.pfc", O_CREAT | O_RDWR | O_TRUNC, 0755);
        
        write(fd, "# pledges: ", strlen("# pledges: "));
        write(fd, mpromises, strlen(mpromises));
        write(fd, "\n", 1);
        seccomp_export_pfc(ctx, fd);
        close(fd);
    #endif


    /* load the seccomp */
    rc = seccomp_load(ctx);
    if (rc)
    {
        goto out;
    }

out:
    free(mpromises);

    seccomp_release(ctx);

    return rc;
}