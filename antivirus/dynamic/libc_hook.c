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