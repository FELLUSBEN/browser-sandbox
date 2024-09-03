import os
from time import sleep

path = './passwords.txt'
last_access = 0

def main():
    CreateFile(path)
    while(True):
        sleep(5)
        if not os.path.getatime(path) == last_access:
            print('Caught by the honeypot!')
            break
    print('Malicous file detected!')

def CreateFile(path):
    with open(path, 'w') as file:
        file.write('Caught by the honeypot!')
    global last_access
    last_access = os.path.getatime(path)

if __name__ == "__main__":
    main()