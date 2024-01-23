#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

//to compile run - gcc -shared -fPIC -o libapilog.so libc_hook.c -ldl

static int (*original_open)(const char *pathname, int flags, mode_t mode) = NULL;
static ssize_t (*original_write)(int fd, const void *buf, size_t count) = NULL;
static int (*original_execvp)(const char *file, char *const argv[]) = NULL;
static int (*original_execve)(const char *pathname, char *const argv[], char *const envp[]) = NULL;
static int (*original_execv)(const char *pathname, char *const argv[]) = NULL;
static int (*original_system)(const char *command) = NULL;
static int (*original_setuid)(uid_t uid) = NULL;
static int (*original_setgid)(gid_t gid) = NULL;
static int (*original_chmod)(const char *pathname, mode_t mode) = NULL;
static int (*original_chown)(const char *pathname, uid_t owner, gid_t group) = NULL;


void log_exec_call(const char*, const char*, char *const[]);

//delete the LD_PRELOAD environment variable after the lib is loaded
void __attribute__((constructor)) library_init(){
        unsetenv("LD_PRELOAD");
}

FILE *logfile = NULL;

void init_logging() {
    logfile = fopen("apilog.txt", "a");
    if (logfile == NULL) {
        perror("Error opening log file");
        exit(EXIT_FAILURE);
    }
}

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;

    if (!logfile) {
        init_logging();
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (!original_open) {
        original_open = (int (*)(const char *, int, mode_t))dlsym(RTLD_NEXT, "open");
    }

    fprintf(logfile, "open called on: %s\n", pathname);
    fflush(logfile);

    return original_open(pathname, flags, mode);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!logfile) {
        init_logging();
    }

    if (!original_write) {
        original_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
    }
    fprintf(logfile, "write called with fd %d and count %zu\n", fd, count);
    fflush(logfile);

    return original_write(fd, buf, count);
}

int execvp(const char *file, char *const argv[]) {
    if (!logfile) {
        init_logging();
    }

    if (!original_execvp) {
        original_execvp = (int (*)(const char *, char *const[]))dlsym(RTLD_NEXT, "execvp");
    }

    fprintf(logfile, "execvp called with command: %s\n", file);
    for (int i = 0; argv[i] != NULL; i++) {
        fprintf(logfile, "  arg[%d]: %s", i, argv[i]);
    }
    fprintf(logfile, "\n");
    fflush(logfile);

    return original_execvp(file, argv);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (!original_execve) {
        original_execve = (int (*)(const char *, char *const[], char *const[]))dlsym(RTLD_NEXT, "execve");
    }

    log_exec_call("execve", pathname, argv);

    return original_execve(pathname, argv, envp);
}


int execv(const char *pathname, char *const argv[]) {
    if (!original_execv) {
        original_execv = (int (*)(const char *, char *const[]))dlsym(RTLD_NEXT, "execv");
    }

    log_exec_call("execv", pathname, argv);

    return original_execv(pathname, argv);
}

int system(const char *command) {
    if (!original_system) {
        original_system = (int (*)(const char *))dlsym(RTLD_NEXT, "system");
    }

    if (logfile) {
        fprintf(logfile, "system called with command: %s\n", command);
        fflush(logfile);
    }

    return original_system(command);
}

void log_exec_call(const char *func_name, const char *pathname, char *const argv[]) {
    if (!logfile) {
        init_logging();
    }
    fprintf(logfile, "%s called with pathname: %s |", func_name, pathname);
    for (int i = 0; argv[i] != NULL; i++) {
         fprintf(logfile, "  arg[%d]: %s", i, argv[i]);
    }
    fprintf(logfile, "\n");
    fflush(logfile);

}

int setuid(uid_t uid) {
    if (!original_setuid) {
        original_setuid = (int (*)(uid_t))dlsym(RTLD_NEXT, "setuid");
    }

    if (!logfile) {
        init_logging();
    }
    fprintf(logfile, "setuid called with uid: %d\n", uid);
    fflush(logfile);

    return original_setuid(uid);
}


int setgid(gid_t gid) {
    if (!original_setgid) {
        original_setgid = (int (*)(gid_t))dlsym(RTLD_NEXT, "setgid");
    }

    if (!logfile) {
        init_logging();
    }
    fprintf(logfile, "setgid called with gid: %d\n", gid);
    fflush(logfile);

    return original_setgid(gid);
}

int chmod(const char *pathname, mode_t mode) {
    if (!original_chmod) {
        original_chmod = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "chmod");
    }

    if (!logfile) {
        init_logging();
    }
    fprintf(logfile, "chmod called on %s with mode: %o\n", pathname, mode);
    fflush(logfile);

    return original_chmod(pathname, mode);
}

int chown(const char *pathname, uid_t owner, gid_t group) {
    if (!original_chown) {
        original_chown = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");
    }

    if (!logfile) {
        init_logging();
    }
    fprintf(logfile, "chown called on %s with owner: %d and group: %d\n", pathname, owner, group);
    fflush(logfile);


    return original_chown(pathname, owner, group);
}