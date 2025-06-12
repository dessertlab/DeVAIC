import os
import sys

# Folder Path
script_dir = os.path.dirname(os.path.abspath(__file__))

path_in = os.path.join(script_dir, "code_test") # folder with .py source code
path_out = os.path.join(script_dir, "file_snippet") # folder that will contain the txt file with the previous .py file converted in single line code
out_filname = "snippets.txt"
  
# Change the directory
os.chdir(path_in)
  
data=list()

# Read File  
def read_file(file_path):
    for i,line in enumerate(open(file_path)):       
        new_line=line.replace("\n","\\n ")
        data.append(new_line)

    return data

# Write File
def write_file(data, file_out):
    with open(file_out, 'w') as f1:
        f1.writelines(data)
        f1.close()

  
print('walk_dir = ' + path_in)

for root, subdirs, files in os.walk(path_in):
    print('--\nroot = ' + root)
    list_file_path = os.path.join(root, 'my-directory-list.txt')

    with open(list_file_path, 'wb') as list_file:
        for subdir in subdirs:
            print('\t- subdirectory ' + subdir)
        
        for filename in files:
            file_path1 = os.path.join(root, filename)

            print('\t- file %s (full path: %s)' % (filename, file_path1))
            if filename.endswith("py"):
                file_path = file_path1
                file_path_out = f"{path_out}/{out_filname}"
                print(file_path_out)
        
                # call read file function
                data= read_file(file_path)
                data.append("\n")
                
                write_file(data, file_path_out)
                