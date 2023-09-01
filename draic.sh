#!/bin/bash

echo -e "\n\n"


echo "██████╗ ██████╗  █████╗ ██╗ ██████╗"
echo "██╔══██╗██╔══██╗██╔══██╗██║██╔════╝"
echo "██║  ██║██████╔╝███████║██║██║     "
echo "██║  ██║██╔══██╗██╔══██║██║██║     "
echo "██████╔╝██║  ██║██║  ██║██║╚██████╗"
echo "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝"
                                   

echo -e "\n\n"

#Detection and Remediation tool for AI-generated Code

SRC_DIR=$PWD
INP_DIR=$SRC_DIR"/input"
SCRIPT_DIR=$SRC_DIR"/script_py"
RES_DIR=$SRC_DIR"/results"
GEN_DIR=$SRC_DIR"/generated_file"
PATH_1="/opt/homebrew/opt/grep/libexec/gnubin"
PATH_2="/usr/local/opt/grep/libexec/gnubin"

name_os=$(uname)
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")


#----------     ADJUSTING THE FILENAME      ----------
echo "$1" | grep -q "/"
if [ $? -eq 0 ]; then
    new_name=$(echo $1 | awk -F "/" '{print $2}' )
else
    new_name=$1
fi

filename_res="[$timestamp]"_"$new_name"
type=$(echo $filename_res | awk -F '.' '{print $2}')


echo "$1" | grep -q ".txt"
if [ $? -eq 1 ]; then
    filename_res=$(echo $filename_res | sed "s/.$type/.txt/g")
fi

#define the names of the generated files
det_file="DET_$filename_res"
rem_file="REM_$filename_res"
cng_file="CNG_$filename_res"
input_file="INPUT_$filename_res"
tmp_file="MOD_INPUT_$filename_res"

#define the paths of the generated files
det_path=$RES_DIR/detection/$det_file
rem_path=$RES_DIR/remediation/$rem_file
cng_path=$RES_DIR/changes/$cng_file
input_path=$GEN_DIR/$input_file
tmp_path=$GEN_DIR/$tmp_file


#----------     CONVERTING JSON TO TXT      ----------
if [ $type == "json" ]; then
    cat $1 | grep -q "\"code\":"
    if [ $? -eq 0 ]; then
        python $SCRIPT_DIR/convert_json_to_txt.py $1 $tmp_path
    else
        python $SCRIPT_DIR/convert_json_wo_keys.py $1 $tmp_path
    fi
fi

### ----------      SETUP       ----------
if [ $name_os = "Darwin" ]; then  #MAC-OS system

    ls $PATH_1 > /dev/null 2>&1;
    if [ $? -eq 0 ]; then   #if the path already exists, it is not exported
        echo $PATH | grep -q "$PATH_1"
        if [ $? -eq 1 ]; then
            export "PATH=$PATH_1:$PATH";
        fi
    else
        ls $PATH_2 > /dev/null 2>&1;
        if [ $? -eq 0 ]; then   #if the path already exists, it is not exported
            echo $PATH | grep -q "$PATH_2"
            if [ $? -eq 1 ]; then
                export "PATH=$PATH_2:$PATH";
            fi
        fi;
    fi
    if [ $type == "json" ]; then
        python $SCRIPT_DIR/preprocessing_macos.py $tmp_path $input_path
        rm $tmp_path
    elif [ $type == "txt" ]; then
        python $SCRIPT_DIR/preprocessing_macos.py $1 $input_path
    fi

elif [ $name_os = "Linux" ]; then #LINUX system
    if [ $type == "json" ]; then
        python $SCRIPT_DIR/preprocessing.py $tmp_path $input_path
        rm $tmp_path
    elif [ $type == "txt" ]; then
        python $SCRIPT_DIR/preprocessing.py $1 $input_path
    fi
fi


#----------     LAUNCHING THE TOOL     ----------
echo -e "[***] Vulnerability Scanning & Remediation...\n"

$SRC_DIR/tool_derem.sh $input_path $det_path $rem_path $cng_path 2> /dev/null