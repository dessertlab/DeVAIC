import sys

print("[***] Processing data...")

input_file = sys.argv[1]

output_file = sys.argv[2]

data=list()

for i, line in enumerate(open(input_file)):
    if line.strip():
        new_line=line.replace("\",\n","\n")
        new_line=new_line.replace("\"\n","\n")
        new_line=new_line.replace("\\\"","'") 
        new_line=new_line.replace("request.form [","request.form[")
        new_line=new_line.replace("request.files [","request.files[")
        new_line=new_line.replace("request.args [","request.args[")
        new_line=new_line.replace(" ''","\\\"")
        new_line=new_line.replace("*","PRODUCT_SYMBOL")
        new_line=new_line.replace("[\\\" ","[\\\"")
        new_line=new_line.replace("(\\\" ","(\\\"")
        new_line=new_line.replace(", \\\" ",", \\\"")
        new_line=new_line.replace(" \']","\']")
        new_line=new_line.replace("request.args.get [","request.args.get[")
        new_line=new_line.replace("session [","session[")
        new_line=new_line.replace("\\n","\\\\\\n")

        data.append(new_line)

data.append("\n")

with open(output_file, 'w') as f:
    f.writelines(data)

