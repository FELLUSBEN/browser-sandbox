import subprocess
import os

def run_with_preload(command):
    lib_path = '/home/ben/test/libapilog.so' # path to libc hook

    env = os.environ.copy()
    env['LD_PRELOAD'] = lib_path

    subprocess.run(command, env=env)

if __name__ == '__main__':
    suspicious_file = './a.out' # replace with file name
    run_with_preload(suspicious_file)