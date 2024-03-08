import yara
import os

directory_path = './yara-rules/malware' #The directory that will contain all of the rules


def GetAllRules():
    # Get file names and paths for all files in the directory
    files = {}
    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path):
            files[file_name] = file_path
    return files

rules = GetAllRules()

compiled_rules = {}
# compiling all the yara rules into a dictionary {filename:compiled file}
for file_name, file_path in rules.items():
    with open(file_path, 'r') as file_content:
        temp = yara.compile(source=file_content.read())
        compiled_rules[file_name] = temp

#now we can use our rules to run on files ex: matches = rules.match('/foo/bar/my_huge_file', timeout=60)
#checkin if any rule of our data base rules is matching the file, if so the file is malicous, if the test go without any matches the file is safe to use.
def CheckFile(path,timeout=60):
    for key in compiled_rules.keys:
        if(compiled_rules[key].match(path,timeout)):
            return "Seems to be malicous by yara rule - ", key
    return "The file is safe from yara rules"
