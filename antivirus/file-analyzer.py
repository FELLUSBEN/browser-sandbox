import tkinter as tk
from tkinter import messagebox

class file_anylzer:
    def __init__(self, path) -> None:
        self.downloads_path = path    
    
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
    file_anylzer = file_anylzer("/downloads") # change path
    file_anylzer.file_check_system()
