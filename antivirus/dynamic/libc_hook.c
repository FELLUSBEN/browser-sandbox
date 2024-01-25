#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

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

char* SOCKET_PATH = NULL;

void log_exec_call(const char*, const char*, char *const[]);

void __attribute__((constructor)) library_init(){
	SOCKET_PATH = getenv("SOCKET_PATH");
	//printf("===%s===",SOCKET_PATH);
	//unsetenv("SOCKET_PATH");
	unsetenv("LD_PRELOAD");
}


void send_log_via_socket(const char *message) {
    struct sockaddr_un addr;
    int fd;

    if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
        perror("socket error");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    //printf("===%s===",SOCKET_PATH);
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (sendto(fd, message, strlen(message), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("sendto error");
        close(fd);
        return;
    }

    close(fd);
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

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (!original_open) {
        original_open = (int (*)(const char *, int, mode_t))dlsym(RTLD_NEXT, "open");
    }

    char message[256];
    snprintf(message, sizeof(message), "open called on: %s", pathname);
    send_log_via_socket(message);
   
    return original_open(pathname, flags, mode);
}

ssize_t write(int fd, const void *buf, size_t count) {

    if (!original_write) {
        original_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
    }

    char message[256];
    snprintf(message, sizeof(message), "write called with fd %d and count %zu", fd, count);
    send_log_via_socket(message);

    return original_write(fd, buf, count);
}


int execvp(const char *file, char *const argv[]) {

    if (!original_execvp) {
        original_execvp = (int (*)(const char *, char *const[]))dlsym(RTLD_NEXT, "execvp");
    }

    log_exec_call("execv", file, argv);
    
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

    log_exec_call("execv", pathname, argv); // Reuse the same logging function

    return original_execv(pathname, argv);
}

int system(const char *command) {
    if (!original_system) {
        original_system = (int (*)(const char *))dlsym(RTLD_NEXT, "system");
    }
    
    char message[256];
    snprintf(message, sizeof(message), "system called with: %s", command);
    send_log_via_socket(message);
    
    return original_system(command);
}

void log_exec_call(const char *func_name, const char *pathname, char *const argv[]) {
    char message[1024];
    snprintf(message, sizeof(message), "execve called: Path: %s, Args: ", pathname);

    for (int i = 0; argv[i] != NULL; i++) {
        strncat(message, argv[i], sizeof(message) - strlen(message) - 1);
        strncat(message, " ", sizeof(message) - strlen(message) - 1);
    }

    send_log_via_socket(message);
}


int setuid(uid_t uid) {
    if (!original_setuid) {
        original_setuid = (int (*)(uid_t))dlsym(RTLD_NEXT, "setuid");
    }

    char message[256];
    snprintf(message, sizeof(message), "setuid called with uid: %d", uid);
    send_log_via_socket(message);

    return original_setuid(uid);
}

int setgid(gid_t gid) {
    if (!original_setgid) {
        original_setgid = (int (*)(gid_t))dlsym(RTLD_NEXT, "setgid");
    }

    char message[256];
    snprintf(message, sizeof(message), "setgid called with gid: %d", gid);
    send_log_via_socket(message);
    
    return original_setgid(gid);
}

int chmod(const char *pathname, mode_t mode) {
    if (!original_chmod) {
        original_chmod = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "chmod");
    }

    char message[256];
    snprintf(message, sizeof(message), "chmod called on %s with mode: %o", pathname, mode);
    send_log_via_socket(message);

    return original_chmod(pathname, mode);
}

int chown(const char *pathname, uid_t owner, gid_t group) {
    if (!original_chown) {
        original_chown = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");
    }

    char message[256];
    snprintf(message, sizeof(message), "chown called on %s with owner: %d and group: %d", pathname, owner, group);
    send_log_via_socket(message);

    return original_chown(pathname, owner, group);
}

