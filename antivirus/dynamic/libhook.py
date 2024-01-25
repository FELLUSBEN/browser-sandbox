import subprocess
import os
import socket
import threading
import uuid

SOCKET_PATH = f"/tmp/socket_{uuid.uuid4()}"

#add more suspicious functions
suspicious_function_calls = {
        "echo": ["hello"],
        "cat": ["/etc/issue", "/etc/*-release", "/etc/lsb-release", "/etc/redhat-release",
                "/proc/version", "/etc/profile", "/etc/bashrc", "/root/.bash_profile",
                "/root/.bashrc", "/root/.bash_logout", "/etc/passwd", "/etc/group",
                "/etc/shadow", "/var/apache2/config.inc", "/var/lib/mysql/mysql/user.MYD",
                "/root/anaconda-ks.cfg"],
        "uname": ["-a", "-mrs"],
        "rpm": ["-q kernel"],
        "dmesg": ["| grep Linux"],
        "ls": ["/boot | grep vmlinuz-", "/usr/bin/", "/sbin/", "/var/cache/apt/archivesO",
                "/var/cache/yum/", "/etc/", "/root/", "/home/", "/var/www/", "/srv/www/htdocs/",
                "/usr/local/www/apache22/data/", "/opt/lampp/htdocs/", "/var/www/html/"],
        "ps": ["aux", "-ef", "aux | grep root", "-ef | grep root"],
        "dpkg": ["-l"],
        "crontab": ["-l"],
        "lsof": ["-i", "-i :80"],
        "netstat": ["-antup", "-antpx", "-tulpn"],
        "find": ["/ -name perl*", "/ -name python*", "/ -name gcc*", "/ -name cc",
                 "/ -name wget", "/ -name nc*", "/ -name netcat*", "/ -name tftp*", "/ -name ftp",
                 "/ -perm -1000 -type d 2>/dev/null", "/ -perm -g=s -type f 2>/dev/null",
                "/ -perm -u=s -type f 2>/dev/null", "/ -writable -type d 2>/dev/null",
                "/ -perm -222 -type d 2>/dev/null", "/ -perm -o+w -type d 2>/dev/null",
                "/ -perm -o+x -type d 2>/dev/null"]
    }


def is_suspicious(syscall):
    function, arguments = "", []
    if "exec" in syscall:
        function = syscall.split("Args: ")[1].split(" ")[0]
        for arg in syscall.split("Args: ")[1].split(" ")[1:]:
            arguments.append(arg)

    if function in suspicious_function_calls:
        for arg in arguments:
            if arg in suspicious_function_calls[function]:
                return True
    return False


def run_with_preload(command):
    lib_path = '/home/ben/test/libapilog.so'

    env = os.environ.copy()
    env['LD_PRELOAD'] = lib_path
    env['SOCKET_PATH'] = SOCKET_PATH

    subprocess.run(command, env=env)

def syscall_handler():
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(SOCKET_PATH)

    print("Socket server listening...")

    while True:
        datagram = server.recv(1024)
        if not datagram:
            continue
        else:
            if is_suspicious(datagram.decode('utf-8')):
                print("\nsuspicious syscall!!!") # add functionality
            print(datagram.decode('utf-8'))
    
    server.close()
    os.remove(SOCKET_PATH)

if __name__ == '__main__':
    command = './a.out'  # Replace with your command
    #syscall_handler()
    t = threading.Thread(target=syscall_handler)
    t.start()
    run_with_preload(command)

