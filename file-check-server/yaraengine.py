import yara
import os

directory_path = './malware'

class engine():
    def GetAllRules(self):
        files = {}
        for file_name in os.listdir(directory_path):
            file_path = os.path.join(directory_path, file_name)
            if os.path.isfile(file_path):
                files[file_name] = file_path
        return files

    def __init__(self):
        rules = self.GetAllRules()
        self.compiled_rules = {}
        for file_name, file_path in rules.items():
            #print(file_name)
            try:
                with open(file_path, 'r') as file_content:
                    temp = yara.compile(source=file_content.read())
                    self.compiled_rules[file_name] = temp
            except Exception as e:
                os.remove(file_path)

    def CheckFile(self,path,timeout=60):
        for key in self.compiled_rules:
            if(self.compiled_rules[key].match(path,timeout)):
                return True
        return False