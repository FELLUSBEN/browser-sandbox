import yara
import os

directory_path = '/yara-rules' #The directory that will contain all of the rules


def GetAllRules():
    # Get file names and paths for all files in the directory
    files = {}
    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path):
            files[file_name] = file_path
    return files

rules = yara.compile(filepaths={
    GetAllRules()
})

#now we can use our rules to run on files ex: matches = rules.match('/foo/bar/my_huge_file', timeout=60)


print(GetAllRules())