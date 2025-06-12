import sys

print("[***] Json to txt convertion...")

input_file = sys.argv[1]

output_file = sys.argv[2]


data=list()

for i, line in enumerate(open(input_file)): 
    if line.strip():
        new_line = line.strip()
        new_line=new_line[1:]
        new_line=new_line.replace("\",","\n")
        new_line=new_line.replace("\\n","n")
        if i != 0:
            data.append(new_line)
    else:
        data.append(new_line)


data.append("\n")


with open(output_file, 'w') as f:
    f.writelines(data)