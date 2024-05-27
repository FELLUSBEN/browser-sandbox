import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEvent, FileSystemEventHandler
import time
from static import yaraengine
from dynamic import libhook
import threading
#from static import yaraengine

class Watcher(FileSystemEventHandler):
    def on_created(self, event: FileSystemEvent) -> None:
        print(f"new file/dir created : {event.src_path}")
        temp = ''
        temp = yaraengine.CheckFile(event.src_path)
        if temp != 'Clear':
            #yara found a match to a malicous patern
            #self.display_virus_warning(event.src_path, 100)
            #return 'malicious'
            pass
        def dynamic_analysis():
            temp = ''
            stop_event = threading.Event()
            def run_checks():
                nonlocal temp
                temp = libhook.run_hook_checks(event.src_path)
                stop_event.set()
            check_thread = threading.Thread(target=run_checks)
            check_thread.start()
            stop_event.wait(timeout=5) # 5 seconds timeout
            if check_thread.is_alive():
                print("Timeout reached, stopping the checks")
            return temp
        result = dynamic_analysis()
        if result == 'malicious':
            #dynamic analysis found a match to a malicous execution of system command.
            #self.display_virus_warning(event.src_path, 100)
            pass


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
    path = 'D:\\test' # change path
    file_anylzer = file_anylzer(path) 
    file_anylzer.file_check_system()
    
