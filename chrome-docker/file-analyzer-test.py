import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEvent, FileSystemEventHandler
import time
import requests
import json
import os

FILE_CHECK_SERVER_IP = "10.100.102.24"

class Watcher(FileSystemEventHandler):
    def on_created(self, event: FileSystemEvent) -> None:
        #print(f"new file/dir created : {event.src_path}")
        if "crdownload" in event.src_path.split('/')[-1] or "com.google.Chrome" in event.src_path.split('/')[-1]:
            return     

        # run the checks
        # yara - run the yara engine test 

        if not os.path.isfile(event.src_path):
            return
        files = {'file': open(event.src_path, 'rb')}
        url = f"http://{FILE_CHECK_SERVER_IP}:5001/upload"

        r = requests.post(url, files=files).text
        data = json.loads(r)

        if data["is_valid"] == False:
            os.rename(event.src_path, event.src_path +"-malicious")
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Found a potential threat!", f"The file {event.src_path.split('/')[-1]} seems to be malicious!\n")
            root.update_idletasks()
            root.update()
        else:
            os.rename(event.src_path, event.src_path +"-benign")
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Download Complete", f"The file {event.src_path.split('/')[-1]} seems to be benign\n")
            root.update_idletasks()
            root.update()

        # sigma and hooks - write script for sigma rules and run the libhook.py file

            
        #yaraengine.CheckFile(event.src_path)


class file_anylzer:
    def __init__(self, path) -> None:
        self.downloads_path = path
        #watchdog start
        observer = Observer()
        event_handler = Watcher()
        observer.schedule(event_handler, path, recursive= True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()    
    
    def display_virus_warning(self, file_name, score):
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Virus Warning", f"the file {file_name} seems to be malicious!\nour score for this file is: {score} out of a 100")


    #1. check with yara rules
    #2. check with sigma rules
    #3. check with dynamic analysis
    #4. check with honeypot
    def file_anylzer(self, file_path):
        initial_score = 100
        


    def file_check_system(self):
        pass



if __name__ == "__main__":
    path = '/home/user/Downloads' # change path
    file_anylzer = file_anylzer(path) 
    file_anylzer.file_check_system()
    
