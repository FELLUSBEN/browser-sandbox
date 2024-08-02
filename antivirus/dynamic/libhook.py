import subprocess
import os
import socket
import threading
import uuid
import psutil


SOCKET_PATH = f"/tmp/socket_{uuid.uuid4()}"

proc = ""

data = "benign"

malicious_function_calls = {
    "rm": ["-rf /"],
    "dd": ["if=/dev/zero of=/dev/sda"],
    "mkfs.ext4": ["/dev/sda1"],
    "echo": ["c > /proc/sysrq-trigger", "hello"],
    "iptables": ["-F"],
    "shutdown": ["-h now"],
    "poweroff": [""],
    "mv": ["/home/user /dev/null"],
    "find": ["/ -type f -exec rm -rf {} \;"],
    "shred": ["-n 1 -z /dev/sda"],
    "cat": ["/dev/random > /dev/sda"],
    "cp": ["/dev/zero /dev/sda"],
    "chmod": ["-R 777 /"],
    "nc": ["-l -p 1234 -e /bin/bash"],
    "kill": ["-9 1"],
    "userdel": ["root"],
    "wall": ["'System will shutdown in 1 minute'"],
    "ln": ["-sf /dev/null ~/.bashrc"],
    "mprotect": [""]
}

def get_child_pids(pid):
    try:
        process = psutil.Process(pid)
        children = process.children(recursive=True)
        return [child.pid for child in children]
    except psutil.NoSuchProcess:
        return []

def is_suspicious(syscall):
    function, arguments = "", []
    if "exec" in syscall:
        function = syscall.split("Args: ")[1].split(" ")[0]
        for arg in syscall.split("Args: ")[1].split(" ")[1:]:
            arguments.append(arg)

    if function in malicious_function_calls:
        for arg in arguments:
            if arg in malicious_function_calls[function]:
                return True
    return False


def run_with_preload(command):
    global proc
    lib_path = '/home/ben/test/libapilog.so' # change library path

    env = os.environ.copy()
    env['LD_PRELOAD'] = lib_path
    env['SOCKET_PATH'] = SOCKET_PATH

    proc = subprocess.Popen(command, env=env) # remove the stdout


def syscall_handler(command):
    global data
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(SOCKET_PATH)
    print("Socket server listening...")


    while True:
        data = server.recv(1024)
        if not data:
            continue
        else:
            if is_suspicious(data.decode('utf-8')):
                child_pids = get_child_pids(proc.pid)
                for child_pid in child_pids:
                    os.kill(child_pid, 9)
                os.kill(proc.pid, 9)
                
                # root = tk.Tk()
                # root.withdraw()
                # messagebox.showerror("Downloaded File!", f"You downloaded {event.src_path.split('/')[-1]}!\n")
                # root.update_idletasks()
                # root.update()
                
                print("\nsuspicious syscall!!!")
                print(data.decode('utf-8'))
                
                server.close()
                os.remove(SOCKET_PATH)
                data =  "malicious"
                break

            print(data.decode('utf-8'))
    
    server.close()
    os.remove(SOCKET_PATH)

#if __name__ == '__main__':
def run_hook_checks(file):
    command = file  # Replace with your command
    t = threading.Thread(target=syscall_handler, args=(command,))
    t.start()
    run_with_preload(command)
    t.join()
    return data

