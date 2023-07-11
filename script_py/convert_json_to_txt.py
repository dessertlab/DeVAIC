import json
import sys

print("[***] Json to txt convertion...")

input_file = sys.argv[1]
file=json.load(open(input_file))

output_file = sys.argv[2]

data=list()

for i in range(len(file)):
    diz=dict()
    diz={
        "code": str
    }
    diz["code"]=file[i]["code"]
    data.append(diz)


#write json
with open(output_file,'w') as outfile:
    json.dump(data,outfile, indent=0, separators=(',',':'))

data=list()

for i, line in enumerate(open(output_file)):
    new_line=line.replace("\"code\":\"","")
    new_line=new_line.replace("\"\n","\n")
    new_line=new_line.replace("{\n","")
    new_line=new_line.replace("},\n","")
    new_line=new_line.replace("}\n","")
    if i != 0 and line != "]":
        data.append(new_line)


with open(output_file, 'w') as f:
    f.writelines(data)