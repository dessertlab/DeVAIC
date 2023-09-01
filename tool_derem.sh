#!/bin/bash
start=$(date +%s.%N)

input=$1

#tool for DETECTION & REMEDIATION of three types of vulnerabilities
#DET file intro
echo -e "==================>      SNIPPETS DETECTED      <===================" > $2  
echo -e "|                                                                  |" >> $2
echo -e "|           [!] -> Vulnerable code snippets detected               |" >> $2
echo -e "|           Safe Code -> Safe code snippet                         |" >> $2
echo -e "|                                                                  |" >> $2
echo -e "====================================================================\n\n\n" >> $2

#REM file intro
echo -e "==================>      SNIPPETS REMEDIATED      <=================" > $3
echo -e "|                                                                  |" >> $3
echo -e "|      [MOD] -> Safe version of the vulnerable code snippets       |" >> $3
echo -e "|      [NOT_MOD] -> Code snippets not completely safe              |" >> $3
echo -e "|      Safe Code -> Safe code snippet                              |" >> $3
echo -e "|                                                                  |" >> $3
echo -e "====================================================================\n\n" >> $3

#CNG file intro
echo -e "==================>      CHANGES IN REMEDIATION      <===================" > $4
echo -e "|                                                                       |" >> $4
echo -e "|    [VULN] -> Vulnerable code snippets detected                        |" >> $4
echo -e "|    [SAFE] -> Changes to code snippets are shown in CAPITAL LETTERS    |" >> $4
echo -e "|    [NOT_SAFE] -> Code snippets not completely changed                 |" >> $4
echo -e "|                                                                       |" >> $4
echo -e "=========================================================================\n\n" >> $4


countvuln=0; 
dimtestset=0;
taint=0;
kufunc=0;
confprob=0;
tp_kuf=0;
tp_cp=0;
kuf_cp=0;
tp_kuf_cp=0;
contNoMod=0;
contMod=0;

name_os=$(uname) #OS-system

while IFS= read -r line; do

    if [ ! -z "$line" ]; then
        num_occ=0;
        taint_s=0;
        kufunc_s=0;
        confprob_s=0;
        tp_kuf_s=0;
        tp_cp_s=0;
        kuf_cp_s=0;
        tp_kuf_cp_s=0;
        pass=0;
        modify=0;
        rem_line=$line;
        cng_line=$rem_line;
        var=
        vuln=
        ########        START TAINT PROPAGATION         ########
        #RULE 1: if exists a the following pattern: = request.args.get()
        num_occ=$(echo $line | awk -F "request.args.get\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.args.get\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.args.get\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi
                
                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.args.get\\\(" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\) -f$split- )
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_args_GET_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -v -q "if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -v -q "if not $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_args_GET_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                                    cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )                                                    
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_args_GET_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_args_GET_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done




        #RULE 2: if exists a the following pattern: = (..+request.args.get())
        echo $line | grep -E -q "\+request.args.get\(|\+ request.args.get\("
        if [ $? -eq 0 ]; then 
            vuln="$vuln, TP(REQ_ARGS_GET_PLUS)"
            parameters=$(echo $line | awk -F 'request.args.get\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
            path=$(echo $line | awk -F 'request.args.get\\(' '{print $1}' | awk -F  '+' '{print $1}' | awk -F  '\\(' '{print $2}')
            rem_line=$(echo $rem_line | sed "s/+request.args.get($parameters)/+f_p/g" | sed "s/+request.args.get($parameters )/+f_p/g" | sed "s/+ request.args.get($parameters)/+ f_p/g" | sed "s/+ request.args.get($parameters )/+ f_p/g" )
            rem_line="f=request.args.get($parameters) \\n f_p = os.path.join('img/', escape(f)) \\n if os.path.realpath(f_p).startswith(os.path.realpath($path)): \\n $rem_line"
            cng_line=$(echo $cng_line | sed "s/+request.args.get($parameters)/+F_P/g" | sed "s/+request.args.get($parameters )/+F_P/g" | sed "s/+ request.args.get($parameters)/+ F_P/g" | sed "s/+ request.args.get($parameters )/+ F_P/g" )
            cng_line="F=REQUEST.ARGS.GET($parameters) \\n F_P = OS.PATH.JOIN('img/', ESCAPE(F)) \\n IF OS.PATH.REALPATH(F_P).STARTSWITH(OS.PATH.REALPATH($path)): \\n $cng_line"
            modify=1;
            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                let taint_s=taint_s+1;
            fi
        fi



        #RULE 3: if exists a the following pattern: return request.args.get(...)
        echo $line | grep -q "return request.args.get("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.args.get\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    vuln="$vuln, TP(REQ_ARGS_GET_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.args.get($parameters/variable = request.args.get($parameters) return escape(variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.args.get($parameters/VARIABLE = REQUEST.ARGS.GET($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 4: var is the name of the variable before = request.GET.get() and then var is inside brackets
        num_occ=$(echo $line | awk -F "request.GET.get\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.GET.get\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.GET.get\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi   

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.GET.get($var)/request.GET.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.GET.get($var/request.GET.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.GET.get(\\\\\"$var\\\\\", $var/request.GET.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g")
                let split=i;
                let split=split+1;

                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.GET.get\\\(" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\) -f$split- )
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_GET_GET_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_GET_GET_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi	
                                        fi
                                    fi
                                fi
                            fi			
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_GET_GET_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_GET_GET_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi   
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 5: if exists a the following pattern: return request.GET.get(...)
        echo $line | grep -q "return request.GET.get("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.GET.get\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    vuln="$vuln, TP(REQ_GET_GET_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.GET.get($parameters/variable = request.GET.get($parameters) return escape(variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.GET.get($parameters/VARIABLE = REQUEST.GET.GET($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 6: var is the name of the variable before = request.files.get() and then var is inside brackets
        num_occ=$(echo $line | awk -F "request.files.get\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.files.get\\\(" -v i="$i" '{print $i}' | awk -F "=" '{print $1}' | awk '{print $NF}')
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.files.get($var)/request.files.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.files.get($var/request.files.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.files.get(\\\\\"$var\\\\\", $var/request.files.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "request.files.get\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo $new_line | cut -d\) -f$split- )
            fi

            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(REQ_FILES_GET_NEW)"
                                    rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                    cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                    modify=1;
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then   
                                        vuln="$vuln, TP(REQ_FILES_GET_NEW)"	
                                        rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi		
                                fi	
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_FILES_GET_NEW)"
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_FILES_GET_NEW)"
                                                rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                modify=1;
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done


        #RULE 7: if exists a the following pattern: return request.files.get(...)
        echo $line | grep -q "return request.files.get("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.files.get\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    vuln="$vuln, TP(REQ_ARGS_FILES_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.files.get($parameters/variable = request.files.get($parameters) return escape(variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.files.get($parameters/VARIABLE = REQUEST.FILES.GET($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 8: if exists a the following pattern: = request.args[]
        new_line1=$(echo $line | sed "s/+request.args\[/ /g" | sed "s/+ request.args\[/ /g" )
        num_occ=$(echo $new_line1 | awk -F "request.args\\\[" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            
            var=$(echo $new_line1 | awk -F "request.args\\\[" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $new_line1 | awk -F "request.args\\\[" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi   

                #check if there are var not strings
                new_line=$(echo $new_line1 | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args\[$var\]/request.args\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/request.args\[$var/request.args\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args\[\\\\\"$var\\\\\", $var/request.args\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.args\\\[" '{print $2}' | cut -d\] -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\] -f$split- )
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_ARGS_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g" )
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g" )
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_ARGS_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi	
                                fi
                            fi			
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_ARGS_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_ARGS_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 9: if exists a the following pattern: return request.args[...]
        echo $line | grep -q "return request.args\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.args\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                    vuln="$vuln, TP(REQ_ARGS_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.args\[$parameters/variable = request.args[$parameters] return escape[variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.args\[$parameters/VARIABLE = REQUEST.ARGS[$parameters] RETURN ESCAPE[VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi

    

        #RULE 10: if exists a the following pattern: = (..+request.args[])
        echo $line | grep -q "(.*+request.args\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
            if [ $? -eq 0 ]; then
                vuln="$vuln, TP(REQ_ARGS3)"
                parameters=$(echo $line | awk -F 'request.args\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                path=$(echo $line | awk -F 'request.args\\[' '{print $1}' | awk -F  '+' '{print $1}' | awk -F  '\\(' '{print $2}')
                rem_line=$(echo $rem_line | sed "s/+request.args\[$parameters\]/+f_p/g" | sed "s/+request.args\[$parameters \]/+f_p/g" | sed "s/+ request.args\[$parameter\]/+ f_p/g" | sed "s/+ request.args\[$parameters \]/+ f_p/g" )
                rem_line="f=request.args[$parameters] \\n f_p = os.path.join('img/', escape(f)) \\n if os.path.realpath(f_p).startswith(os.path.realpath($path)): \\n $rem_line"
                cng_line=$(echo $cng_line | sed "s/+request.args\[$parameters\]/+F_P/g" | sed "s/+request.args\[$parameters \]/+F_P/g" | sed "s/+ request.args\[$parameter\]/+ F_P/g" | sed "s/+ request.args\[$parameters \]/+ F_P/g" )
                cng_line="F=REQUEST.ARGS[$parameters] \\n F_P = OS.PATH.JOIN('img/', ESCAPE(F)) \\n IF OS.PATH.REALPATH(F_P).STARTSWITH(OS.PATH.REALPATH($path)): \\n $cng_line"
                modify=1;
                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                    let taint_s=taint_s+1;
                fi
            fi
        fi



        #RULE 11: if exists a the following pattern: = request.files[]
        num_occ=$(echo $line | awk -F "request.files\\\[" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.files\\\[" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.files\\\[" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi  

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.files\[$var\]/request.files\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.files\[$var/request.files\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.files\[\\\\\"$var\\\\\", $var/request.files\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.files\\\[" '{print $2}' | cut -d\] -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\] -f$split- )
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_FILES_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_FILES_NEW)"	
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi	
                                        fi
                                    fi
                                fi	
                            fi	
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_FILES_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_FILES_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 12: if exists a the following pattern: return request.files[...]
        echo $line | grep -q "return request.files\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.files\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                    vuln="$vuln, TP(REQ_FILES_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.files\[$parameters/variable = request.files[$parameters] return escape[variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.files\[$parameters/VARIABLE = REQUEST.FILES[$parameters] RETURN ESCAPE[VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi


    
        #RULE 13: if exists a the following pattern: = request.form[]
        num_occ=$(echo $line | awk -F "request.form\\\[" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            echo $line | grep -E -q "in request.form:|in request.form :"
            if [ $? -eq 0 ]; then
                break
            fi
            var=$(echo $line | awk -F "request.form\\\[" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.form\\\[" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.form\[$var\]/request.form\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.form\[$var/request.form\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.form\[\\\\\"$var\\\\\", $var/request.form\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.form\\\[" '{print $2}' | cut -d\] -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\] -f$split- )
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -q "in request.form:| in request.form :"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(REQ_FORM_NEW)"
                                    rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                    cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                    modify=1;
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -q "in request.form:|in request.form :"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_FORM_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi	
                                    fi
                                fi
                            fi		
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -q "in request.form:|in request.form :"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_FORM_NEW)"
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -v -q "in request.form:|in request.form :"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_FORM_NEW)"
                                                rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                modify=1;
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 14: if exists a the following pattern: return request.form[...]
        echo $line | grep -q "return request.form\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.form\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                    vuln="$vuln, TP(REQ_FORM_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.form\[$parameters/variable = request.form[$parameters] return escape[variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.form\[$parameters/VARIABLE = REQUEST.FORM[$parameters] RETURN ESCAPE[VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 15: if exists a the following pattern: = request.GET[]
        num_occ=$(echo $line | awk -F "request.GET\\\[" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.GET\\\[" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.GET\\\[" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.GET\[$var\]/request.GET\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/request.GET\[$var/request.GET\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.GET\[\\\\\"$var\\\\\", $var/request.GET\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.GET\\\[" '{print $2}' | cut -d\] -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\] -f$split- )
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_GET_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_GET_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi		
                                        fi
                                    fi
                                fi	
                            fi	
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_GET_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_GET_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 16: if exists a the following pattern: return request.GET[...]
        echo $line | grep -i -q "return request.GET\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.GET\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                    vuln="$vuln, TP(REQ_GET_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.GET\[$parameters/variable = request.GET[$parameters] return escape[variable/g" | sed "s/return request.get\[$parameters/variable = request.GET[$parameters] return escape[variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.GET\[$parameters/VARIABLE = REQUEST.GET[$parameters] RETURN ESCAPE[VARIABLE/g" | sed "s/return request.get\[$parameters/VARIABLE = REQUEST.GET[$parameters] RETURN ESCAPE[VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 17: if exists a the following pattern: = request.get_data()
        num_occ=$(echo $line | awk -F "request.get_data\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.get_data\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.get_data\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.get_data($var)/request.get_data()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.get_data($var/request.get_data(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.get_data(\\\\\"$var\\\\\", $var/request.get_data(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.get_data\\\(" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\) -f$split- )
                fi
            
                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_GET_DATA_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_GET_DATA_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_GET_DATA_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_GET_DATA_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 18: if exists a the following pattern: return request.get_data(...)
        echo $line | grep -q "return request.get_data("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.get_data\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    vuln="$vuln, TP(REQ_GET_DATA_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.get_data($parameters/variable = request.get_data($parameters) return escape(variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.get_data($parameters/VARIABLE = REQUEST.GET_DATA($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 19: if exists a the following pattern: = request.POST.get()
        num_occ=$(echo $line | awk -F "request.POST.get\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            new_line=$(echo $line | sed "s/== 'POST'/ /g" | sed "s/=='POST'/ /g" )
            var=$(echo $new_line | awk -F "request.POST.get\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.POST.get\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.POST.get($var)/request.POST.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.POST.get($var/request.POST.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.POST.get(\\\\\"$var\\\\\", $var/request.POST.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.POST.get\\\(" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\) -f$split- )
                fi
                
                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_POST_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_POST_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_POST_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_POST_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 20: if exists a the following pattern: = (request.POST.get())
        echo $line | grep -q "(request.POST.get(.*%"
        if [ $? -eq 0 ]; then
            vuln="$vuln, TP(REQ_POST_GET)"
            parameters=$(echo $line | awk -F 'request.POST.get\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
            rem_line=$(echo $rem_line | sed "s/request.POST.get($parameters)/escape(request.POST.get($parameters))/g" | sed "s/request.POST.get($parameters )/escape(request.POST.get($parameters))/g" )
            cng_line=$(echo $cng_line | sed "s/request.POST.get($parameters)/ESCAPE(REQUEST.POST.GET($parameters))/g" | sed "s/request.POST.get($parameters )/ESCAPE(REQUEST.POST.GET($parameters))/g" )
            modify=1;
            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                let taint_s=taint_s+1;
            fi
        fi

        

        #RULE 21: if exists a the following pattern: = request.read()
        num_occ=$(echo $line | awk -F "request.read\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.read\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.read\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.read($var)/request.read()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.read($var/request.read(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.read(\\\\\"$var\\\\\", $var/request.read(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.read\\\(" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\) -f$split- )
                fi
            
                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_READ_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_READ_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_READ_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_READ_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 22: if exists a the following pattern: return request.read(...)
        echo $line | grep -q "return request.read("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.read\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    vuln="$vuln, TP(REQ_READ_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.read($parameters/variable = request.read($parameters) return escape(variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.read($parameters/VARIABLE = REQUEST.READ($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi

        

        #RULE 23: if exists a the following pattern: = request.urlopen()
        num_occ=$(echo $line | awk -F "request.urlopen\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.urlopen\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "request.urlopen\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.urlopen($var)/request.urlopen()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/request.urlopen($var/request.urlopen(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.urlopen(\\\\\"$var\\\\\", $var/request.urlopen(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "request.urlopen\\\(" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\) -f$split- )
                fi
            
                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_URLOPEN_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_URLOPEN_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_URLOPEN_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQ_URLOPEN_NEW)"
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 24: if exists a the following pattern: return request.urlopen(...)
        echo $line | grep -q "return request.urlopen("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.urlopen\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    vuln="$vuln, TP(REQ_URLOPEN_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.urlopen($parameters/variable = request.urlopen($parameters) return escape(variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.urlopen($parameters/VARIABLE = REQUEST.URLOPEN($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi

        

        #RULE 25: if exists a the following pattern: = requests.get()
        num_occ=$(echo $line | awk -F "requests.get\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "requests.get\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "requests.get\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/requests.get($var)/requests.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/requests.get($var/requests.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/requests.get(\\\\\"$var\\\\\", $var/requests.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "requests.get\\\(" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo $new_line | cut -d\) -f$split- )
                fi
            
                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQS_GET_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQS_GET_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQS_GET_NEW)"
                                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                    modify=1;
                                                else
                                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                    if [ $? -eq 0 ]; then
                                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                        modify=1;
                                                    fi
                                                fi
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                                if [ $? -eq 0 ]; then
                                                    vuln="$vuln, TP(REQS_GET_NEW)"
                                                    parameters=$(echo $line | awk -F 'return requests.get\\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/requests.get($var/escape(requests.get($var)/g" )
                                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/requests.get($var/ESCAPE(REQUESTS.GET($var)/g" )
                                                    modify=1;
                                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                        let taint_s=taint_s+1;
                                                    fi
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi

            let i=i+1;
            let check=num_occ+1;
        done
            
            



        #RULE 26: if exists a the following pattern: return requests.get(...)
        echo $line | grep -q "return requests.get("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return requests.get\\\(' '{print $2}' | awk -F  '\\\)' '{print $1}')
                    vuln="$vuln, TP(REQS_GET_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return requests.get($parameters/variable = requests.get($parameters) return escape(variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return requests.get($parameters/VARIABLE = REQUESTS.GET($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi
    


        #RULE 27: var is the name of the variable before = input()
        num_occ=$(echo $line | awk -F "int\\\(input\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "int\\\(input\\\(" -v i="$i" '{print $i}' | awk -F "=" '{print $1}' | awk '{print $NF}')
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "int\\\(input\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo $new_line | cut -d\) -f$split- )
            fi
        
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                        if [ $? -eq 0 ]; then
                            vuln="$vuln, TP(REQ_INPUT1_NEW)"
                            rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                            cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                            modify=1;
                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                let taint_s=taint_s+1;
                            fi
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                            if [ $? -eq 0 ]; then
                                vuln="$vuln, TP(REQ_INPUT1_NEW)"
                                rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                modify=1;
                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                    let taint_s=taint_s+1;
                                fi
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(REQ_INPUT1_NEW)"
                                    echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                    if [ $? -eq 0 ]; then
                                        rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                        cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                        modify=1;
                                    else
                                        echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                        if [ $? -eq 0 ]; then
                                            rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                            cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                            modify=1;
                                        fi
                                    fi
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_INPUT1_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                        cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 28: var is the name of the variable before = input()
        num_occ=$(echo $line | awk -F " input\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F " input\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F " input\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi     
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F " input\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo $new_line | cut -d\) -f$split- )
            fi
        
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                        if [ $? -eq 0 ]; then
                            vuln="$vuln, TP(REQ_INPUT2_NEW)"
                            rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                            cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                            modify=1;
                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                let taint_s=taint_s+1;
                            fi
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                            if [ $? -eq 0 ]; then
                                vuln="$vuln, TP(REQ_INPUT2_NEW)"
                                rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                modify=1;
                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                    let taint_s=taint_s+1;
                                fi
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(REQ_INPUT2_NEW)"
                                    echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b|\[\b$var\b|\[ \b$var\b"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -q "int\(\b$var\b|int\( \b$var\b"
                                        if [ $? -eq 0 ]; then
                                            rem_line=$(echo $rem_line | sed "s/int($var/int(escape($var)/g" | sed "s/int( $var/int(escape($var)/g" )
                                            cng_line=$(echo $cng_line | sed "s/int($var/INT(ESCAPE($var)/g" | sed "s/int( $var/INT(ESCAPE($var)/g" )
                                        else
                                            rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" | sed "s/\[$var/\[escape($var)/g" | sed "s/\[ $var/\[ escape($var)/g" )
                                            cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" | sed "s/\[$var/\[ESCAPE($var)/g" | sed "s/\[ $var/\[ ESCAPE($var)/g" )
                                        fi
                                        modify=1;
                                    else
                                        echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)|\b$var\b\]|\b$var\b \]"
                                        if [ $? -eq 0 ]; then
                                            rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/$var]/escape($var)]/g" |sed "s/$var ]/escape($var) ]/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                            cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/$var]/ESCAPE($var)]/g" |sed "s/$var ]/ESCAPE($var) ]/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                            modify=1;
                                        fi
                                    fi
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_INPUT2_NEW)"
                                        rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                        cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi  
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 29: var is the name of the variable before = ldap3.Server()
        num_occ=$(echo $line | awk -F "ldap3.Server\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "ldap3.Server\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "ldap3.Server\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi 
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/ldap3.Server($var)/ldap3.Server()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/ldap3.Server($var/ldap3.Server(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/ldap3.Server(\\\\\"$var\\\\\", $var/ldap3.Server(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "ldap3.Server\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo $new_line | cut -d\) -f$split- )
            fi

            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var||escape_rdn\( $var"
                    if [ $? -eq 0 ]; then
                        vuln="$vuln, TP(LDAP1_NEW)"
                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                        modify=1;
                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                            let taint_s=taint_s+1;
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                        if [ $? -eq 0 ]; then
                            vuln="$vuln, TP(LDAP1_NEW)"
                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                            modify=1;
                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                let taint_s=taint_s+1;
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                            if [ $? -eq 0 ]; then
                                vuln="$vuln, TP(LDAP1_NEW)"
                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                if [ $? -eq 0 ]; then
                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                    modify=1;
                                else
                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                    if [ $? -eq 0 ]; then
                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                        modify=1;
                                    fi
                                fi
                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                    let taint_s=taint_s+1;
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(LDAP1_NEW)"
                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                    modify=1;
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 30: var is the name of the variable before = ldap_connection.search_s()
        num_occ=$(echo $line | awk -F "ldap_connection.search_s\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "ldap_connection.search_s\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "ldap_connection.search_s\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi 
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/ldap_connection.search_s($var)/ldap_connection.search_s()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/ldap_connection.search_s($var/ldap_connection.search_s(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/ldap_connection.search_s(\\\\\"$var\\\\\", $var/ldap_connection.search_s(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "ldap_connection.search_s\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo $new_line | cut -d\) -f$split- )
            fi
        
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                    if [ $? -eq 0 ]; then
                        vuln="$vuln, TP(LDAP2_NEW)"
                        rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                        cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                        modify=1;
                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                            let taint_s=taint_s+1;
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                        if [ $? -eq 0 ]; then
                            vuln="$vuln, TP(LDAP2_NEW)"
                            rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                            cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                            modify=1;
                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                let taint_s=taint_s+1;
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                            if [ $? -eq 0 ]; then
                                vuln="$vuln, TP(LDAP2_NEW)"
                                echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                if [ $? -eq 0 ]; then
                                    rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                    cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                    modify=1;
                                else
                                    echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                    if [ $? -eq 0 ]; then
                                        rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                        cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                        modify=1;
                                    fi
                                fi
                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                    let taint_s=taint_s+1;
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(LDAP2_NEW)"
                                    rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                    cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                    modify=1;
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        #RULE 31: if exists a the following pattern: = request.args.get[] and == var
        echo $line | grep -q "request.args.get\[.*==[^a-z]*[a-z]*[^a-z]"
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    vuln="$vuln, TP(REQ_ARGS_GET)"
                    parameters=$(echo $line | awk -F 'request.args.get\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                    rem_line=$(echo $rem_line | sed "s/request.args.get\[$parameters\]/escape[request.args.get[$parameters]]/g" | sed "s/request.args.get\[$parameters \]/escape[request.args.get[$parameters]]/g" )
                    cng_line=$(echo $cng_line | sed "s/request.args.get\[$parameters\]/ESCAPE[REQUEST.ARGS.GET[$parameters]]/g" | sed "s/request.args.get\[$parameters \]/ESCAPE[REQUEST.ARGS.GET[$parameters]]/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 32: if exists a the following pattern: return request.args.get[...]
        echo $line | grep -q "return request.args.get\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return request.args.get\\[' '{print $2}' | awk -F  '\\]' '{print $1}')
                    vuln="$vuln, TP(REQ_ARGS_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return request.args.get\[$parameters/variable = request.args.get[$parameters] return escape[variable/g" | sed "s/return request.args.get\[$parameters/variable = request.args.get[$parameters] return escape[variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return request.args.get\[$parameters/VARIABLE = REQUEST.ARGS.GET[$parameters] RETURN ESCAPE[VARIABLE/g" | sed "s/return request.args.get\[$parameters/VARIABLE = REQUEST.ARGS.GET[$parameters] RETURN ESCAPE[VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 33: if exists a the following pattern: = request.args.get()
        num_occ=$(echo $line | awk -F "request.args.get\\\[" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "request.args.get\\\[" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "request.args.get\\\[" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi       
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get\[$var\]/request.args.get\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/request.args.get\[$var/request.args.get\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get\[\\\\\"$var\\\\\", $var/request.args.get\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "request.args.get\\\[" '{print $2}' | cut -d\] -f$split- )
            else
                new_line=$(echo $new_line | cut -d\] -f$split- )
            fi

            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(REQ_ARGS_GET_QUADRA_NEW)"
                                    rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                    cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                    modify=1;
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(REQ_ARGS_GET_QUADRA_NEW)"	
                                        rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                        cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                        modify=1;
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi	
                                    fi
                                fi
                            fi
                        fi		
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(REQ_ARGS_GET_QUADRA_NEW)"
                                            echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                            if [ $? -eq 0 ]; then
                                                rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                                cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                                modify=1;
                                            else
                                                echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                                if [ $? -eq 0 ]; then
                                                    rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                    cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                    modify=1;
                                                fi
                                            fi
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then   
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                            if [ $? -eq 0 ]; then
                                                vuln="$vuln, TP(REQ_ARGS_GET_QUADRA_NEW)"
                                                rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                                cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                                modify=1;
                                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                    let taint_s=taint_s+1;
                                                fi
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        


        #RULE 34: if exists a the following pattern: = urlparse()
        num_occ=$(echo $line | awk -F "urlparse\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "urlparse\\\(" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "urlparse\\\(" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi 
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/urlparse($var)/urlparse()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/urlparse($var/urlparse(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/urlparse(\\\\\"$var\\\\\", $var/urlparse(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "urlparse\\\(" '{print $2}' | cut -d\) -f$split- )
            else
                new_line=$(echo $new_line | cut -d\) -f$split- )
            fi
            
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                            if [ $? -eq 0 ]; then
                                vuln="$vuln, TP(URLPARSE_NEW)"
                                rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                modify=1;
                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                    let taint_s=taint_s+1;
                                fi
                            fi
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(URLPARSE_NEW)"
                                    rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                    cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                    modify=1;
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(URLPARSE_NEW)"
                                        echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b"
                                        if [ $? -eq 0 ]; then
                                            rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" )
                                            cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" )
                                            modify=1;
                                        else
                                            echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)"
                                            if [ $? -eq 0 ]; then
                                                rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                modify=1;
                                            fi
                                        fi
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(URLPARSE_NEW)"
                                            rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                            cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done


        #RULE 35: if exists a the following pattern: urlparse(...).function
        echo $line | grep -P -q "urlparse\(.*?\)\.[a-zA-Z]*"
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\(urlparse\(|escape\( urlparse\("
                if [ $? -eq 0 ]; then
                    vuln="$vuln, TP(URLPARSE_DIRECTLY_USED)"
                    parameters=$(echo $line | awk -F 'urlparse\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    rem_line=$(echo $rem_line | sed "s/urlparse($parameters/escape(urlparse($parameters)/g")
                    cng_line=$(echo $cng_line | sed "s/urlparse($parameters/ESCAPE(URLPARSE($parameters)/g")
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 36: if exists a the following pattern: return urlparse(...)
        echo $line | grep -q "return urlparse("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                if [ $? -eq 0 ]; then
                    parameters=$(echo $line | awk -F 'return urlparse\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                    vuln="$vuln, TP(URLPARSE_RETURN)"
                    rem_line=$(echo $rem_line | sed "s/return urlparse($parameters/variable = urlparse($parameters) return escape(variable/g" | sed "s/return urlparse($parameters/variable = urlparse($parameters) return escape(variable/g" )
                    cng_line=$(echo $cng_line | sed "s/return urlparse($parameters/VARIABLE = URLPARSE($parameters) RETURN ESCAPE(VARIABLE/g" | sed "s/return urlparse($parameters/VARIABLE = URLPARSE($parameters) RETURN ESCAPE(VARIABLE/g" )
                    modify=1;
                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                        let taint_s=taint_s+1;
                    fi
                fi
            fi
        fi



        #RULE 37: if exists a the following pattern: = session[]
        num_occ=$(echo $line | awk -F "session\\\[" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "session\\\[" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "session\\\[" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then #LINUX system
                    var=${var::-1}
                fi
            fi       
            #check if there are var not strings
            new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/session\[$var\]/session\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" | sed "s/'$var'/ /g" | sed "s/session\[$var/session\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/session\[\\\\\"$var\\\\\", $var/session\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" | sed "s/$var()/ /g" )
            let split=i;
            let split=split+1;
            if [ $num_occ -eq 1 ]; then
                new_line=$(echo $new_line | awk -F "session\\\[" '{print $2}' | cut -d\] -f$split- )
            else
                new_line=$(echo $new_line | cut -d\] -f$split- )
            fi

            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                            if [ $? -eq 0 ]; then
                                vuln="$vuln, TP(SESSION)"
                                rem_line=$(echo $rem_line | sed "s/+$var/+escape($var)/g" | sed "s/+ $var/+ escape($var)/g" | sed "s/=$var/=escape($var)/g" | sed "s/= $var/= escape($var)/g")
                                cng_line=$(echo $cng_line | sed "s/+$var/+ESCAPE($var)/g" | sed "s/+ $var/+ ESCAPE($var)/g" | sed "s/=$var/=ESCAPE($var)/g" | sed "s/= $var/= ESCAPE($var)/g")
                                modify=1;
                                if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                    let taint_s=taint_s+1;
                                fi
                            fi
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                if [ $? -eq 0 ]; then
                                    vuln="$vuln, TP(SESSION)"
                                    rem_line=$(echo $rem_line | sed "s/$var:/escape($var):/g" | sed "s/$var :/escape($var) :/g" )
                                    cng_line=$(echo $cng_line | sed "s/$var:/ESCAPE($var):/g" | sed "s/$var :/ESCAPE($var) :/g" )
                                    modify=1;
                                    if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                        let taint_s=taint_s+1;
                                    fi
                                fi
                            fi
                        fi				
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                    if [ $? -eq 0 ]; then
                                        vuln="$vuln, TP(SESSION)"
                                        echo $new_line | grep -E -q "\(\b$var\b|\( \b$var\b|\[\b$var\b|\[ \b$var\b"
                                        if [ $? -eq 0 ]; then
                                            rem_line=$(echo $rem_line | sed "s/($var/(escape($var)/g" | sed "s/( $var/( escape($var)/g" | sed "s/\[$var/\[escape($var)/g" | sed "s/\[ $var/\[ escape($var)/g" )
                                            cng_line=$(echo $cng_line | sed "s/($var/(ESCAPE($var)/g" | sed "s/( $var/( ESCAPE($var)/g" | sed "s/\[$var/\[ESCAPE($var)/g" | sed "s/\[ $var/\[ ESCAPE($var)/g" )
                                            modify=1;
                                        else
                                            echo $new_line | grep -E -q "\b$var\b\)|\b$var\b \)|\b$var\b\]|\b$var\b \]"
                                            if [ $? -eq 0 ]; then
                                                rem_line=$(echo $rem_line | sed "s/$var)/escape($var))/g" | sed "s/$var )/escape($var) )/g" | sed "s/$var]/escape($var)]/g" |sed "s/$var ]/escape($var) ]/g" | sed "s/% $var/% escape($var)/g" | sed "s/%$var/%escape($var)/g"  )
                                                cng_line=$(echo $cng_line | sed "s/$var)/ESCAPE($var))/g" | sed "s/$var )/ESCAPE($var) )/g" | sed "s/$var]/ESCAPE($var)]/g" |sed "s/$var ]/ESCAPE($var) ]/g" | sed "s/% $var/% ESCAPE($var)/g" | sed "s/%$var/%ESCAPE($var)/g"  )
                                                modify=1;
                                            fi
                                        fi
                                        if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                            let taint_s=taint_s+1;
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], check=True|subprocess.run\(.*(\b$var\b).*?\], check =True|subprocess.run\(.*(\b$var\b).*?\], check= True|subprocess.run\(.*(\b$var\b).*?\], check = True|subprocess.run\(.*(\b$var\b).*?\],check=True|subprocess.run\(.*(\b$var\b).*?\],check =True|subprocess.run\(.*(\b$var\b).*?\],check= True|subprocess.run\(.*(\b$var\b).*?\],check = True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                                        if [ $? -eq 0 ]; then
                                            vuln="$vuln, TP(SESSION)"
                                            rem_line=$(echo $rem_line | sed "s/return $var/return escape($var)/g" | sed "s/$var./escape($var)./g" )
                                            cng_line=$(echo $cng_line | sed "s/return $var/RETURN ESCAPE($var)/g" | sed "s/$var./ESCAPE($var)./g" )
                                            modify=1;
                                            if [ $taint_s -eq 0 ]; then #I count the single category occurence per snippet
                                                let taint_s=taint_s+1;
                                            fi
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done



        ########        START KNOWN UNSAFE FUNCTIONS            ########
        #RULE 38: detection of yaml.load() function
        echo $line | grep -q -i " yaml\.load("
        if [ $? -eq 0 ]; then
            vuln="$vuln, KUF(YAML_LOAD)"
            rem_line=$(echo $rem_line | sed "s/yaml.load(/yaml.safe_load(/g")
            cng_line=$(echo $cng_line | sed "s/yaml.load(/YAML.SAFE_LOAD(/g")
            modify=1;
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 39: detection of eval() function
        echo $line | grep -E -q -i "\(eval\(| eval\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "def eval("
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(EVAL)"
                rem_line=$(echo $rem_line | sed "s/eval(/ast.literal_eval(/g")
                cng_line=$(echo $cng_line | sed "s/eval(/AST.LITERAL_EVAL(/g")
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 40: detection of exec() function
        echo $line | grep -q -i "exec("
        if [ $? -eq 0 ]; then
            vuln="$vuln, KUF(EXEC)"
            modify=2; #NOT MOD
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 41: detection of traceback.format_exc() function without saving output in a variable
        var=$(echo $line | awk -F "traceback.format_exc\\\(" '{print $1}' |  awk '{print $NF}')
        if [ -z "$var" ]; then
                pass=1;
        else
            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "traceback.format_exc\\\(" '{print $1}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $last_char == "=" ]; then
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi            
            fi   
            ### CHECK  
            echo $line | grep -E -q -i "return traceback.format_exc\(\)|print\($var\)|print\($var\)|print\( $var\)|print\($var \)|print\( $var \)"
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(TRACEBACK)"
                rem_line=$(echo $rem_line | sed "s/print($var)/ /g" | sed "s/print( $var)/ /g" | sed "s/print($var )/ /g" | sed "s/print( $var )/ /g" | sed "s/return traceback.format_exc/ trace_var = traceback.format_exc/g")
                cng_line=$(echo $cng_line | sed "s/print($var)/ /g" | sed "s/print( $var)/ /g" | sed "s/print($var )/ /g" | sed "s/print( $var )/ /g" | sed "s/return traceback.format_exc/ TRACE_VAR = TRACEBACK.FORMAT_EXC/g")
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 42: detection of run(debug=True) function
        echo $line | grep -E -q -i "run\(debug=True\)|.run\(debug=True\)|run\( debug=True \)|.run\( debug=True \)|run\( debug=True\)|.run\( debug=True\)|run\(debug=True \)|.run\(debug=True \)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]run("
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(DEBUG_TRUE)"
                rem_line=$(echo $rem_line | sed "s/(debug=True/(debug=True, use_debugger=False, use_reloader=False/g")
                cng_line=$(echo $cng_line | sed "s/(debug=True/(DEBUG=TRUE, USE_DEBUGGER=FALSE, USE_RELOADER=FALSE/g")
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 43: detection of ftplib.FTP() function
        echo $line | grep -E -q -i "ftplib.FTP\(|FTP\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]FTP("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -i -q " FTP()"
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(FTP)"
                    rem_line=$(echo $rem_line | sed "s/ftplib.FTP(/ftplib.FTP_TLS(/g")
                    cng_line=$(echo $cng_line | sed "s/ftplib.FTP(/FTPLIB.FTP_TLS(/g")
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi



        #RULE 44: detection of smtplib.SMTP() function
        echo $line | grep -E -q -i "smtplib.SMTP\(|SMTP\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]SMTP("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -i -q " SMTP()"
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(SMTP)"
                    rem_line=$(echo $rem_line | sed "s/smtplib.SMTP(/smtplib.SMTP_SSL(/g")
                    cng_line=$(echo $cng_line | sed "s/smtplib.SMTP(/SMTPLIB.SMTP_SSL(/g")
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi



        #RULE 45: detection of hashlib.sha256() function
        echo $line | grep -E -q -i "hashlib.sha256\(|sha256\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]sha256("
            if [ $? -eq 0 ]; then
            echo $line | grep -v -i -q " sha256("
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(SHA256)"
                    rem_line=$(echo $rem_line | sed "s/hashlib.sha256(/hashlib.sha512(/g" | sed "s/sha256(/sha512(/g")
                    cng_line=$(echo $cng_line | sed "s/hashlib.sha256(/HASHLIB.SHA512(/g" | sed "s/sha256(/SHA512(/g")
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi



        #RULE 46: detection of DSA.generate() function with value less (or equal) than 1024
        echo $line |  grep -E -i -q "DSA.generate\((0|1|2|4|8|16|32|64|128|256|512|1024|)\)"
        if [ $? -eq 0 ]; then
            value=$(echo $line | awk -F 'DSA.generate\\(' '{print $2}' | awk -F  ')' '{print $1}')
            vuln="$vuln, KUF(DSA)"
            rem_line=$(echo $rem_line | sed "s/DSA.generate($value/DSA.generate(2048/g" | sed "s/DSA.generate( $value/DSA.generate(2048/g")
            cng_line=$(echo $cng_line | sed "s/DSA.generate($value/DSA.GENERATE(2048/g" | sed "s/DSA.generate( $value/DSA.GENERATE(2048/g")
            modify=1;
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 47: detection of DES.new() function
        echo $line | grep -q -i " DES.new("
        if [ $? -eq 0 ]; then
            vuln="$vuln, KUF(DES)"
            rem_line=$(echo $rem_line | sed "s/DES.new(/sha512.new(/g" )
            cng_line=$(echo $cng_line | sed "s/DES.new(/SHA512.NEW(/g" )
            modify=1;
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 48: detection of ssl.wrap_socket() function
        echo $line | grep -q -i "ssl.wrap_socket("
        if [ $? -eq 0 ]; then
            vuln="$vuln, KUF(SSL_WRAP_SOCKET)"
            rem_line=$(echo $rem_line | sed "s/ssl.wrap_socket(/SSLContext.wrap_socket(/g")
            cng_line=$(echo $cng_line | sed "s/ssl.wrap_socket(/SSLCONTEXT.WRAP_SOCKET(/g")
            modify=1;
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 49: detection of hashlib.md5() function
        echo $line | grep -E -q -i "hashlib.md5\(|md5\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]md5("
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(MD5)"
                rem_line=$(echo $rem_line | sed "s/hashlib.md5(/hashlib.sha512(/g" | sed "s/md5(/sha512(/g")
                cng_line=$(echo $cng_line | sed "s/hashlib.md5(/HASHLIB.SHA512(/g" | sed "s/md5(/SHA512(/g")
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 50: detection of hashlib.sha1() function
        echo $line | grep -E -q -i "hashlib.sha1\(|sha1\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]sha1("
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(SHA1)"
                rem_line=$(echo $rem_line | sed "s/hashlib.sha1(/hashlib.sha512(/g" | sed "s/sha1(/sha512(/g")
                cng_line=$(echo $cng_line | sed "s/hashlib.sha1(/HASHLIB.SHA512(/g" | sed "s/sha1(/SHA512(/g")
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 51: detection of algorithms.AES() function
        new_line=$(echo $line | sed "s/AES(__name__)/ /g" | sed "s/def AES(/def func(/g" | sed "s/return AES():/ /g" | sed "s/AES =/ /g" | sed "s/AES=/ /g" )
        echo $new_line | grep -E -q -i "algorithms.AES\(|AES\("
        if [ $? -eq 0 ]; then
            echo $new_line | grep -v -q "[a-zA-Z0-9]AES("
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(AES_ALG)"
                rem_line=$(echo $rem_line | sed "s/algorithms.AES/algorithms.sha512/g" | sed "s/AES(/sha512(/g" )
                cng_line=$(echo $cng_line | sed "s/algorithms.AES/ALGORITHMS.SHA512/g" | sed "s/AES(/SHA512(/g" )
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 52: detection of modes.CBC() function
        echo $line | grep -E -q -i "modes.CBC\(|AES.MODE_CBC"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]CBC("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def CBC("
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(CBC)"
                    rem_line=$(echo $rem_line | sed "s/AES.MODE_CBC/AES.MODE_GCM/g" | sed "s/modes.CBC/modes.GCM/g" )
                    cng_line=$(echo $cng_line | sed "s/AES.MODE_CBC/AES.MODE_GCM/g" | sed "s/modes.CBC/MODES.GCM/g" )
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi




        #RULE 53: detection of random.randint() function
        echo $line | grep -E -q -i "random.randint\(|randint\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]randint("
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(RANDINT)"
                rem_line=$(echo $rem_line | sed "s/random.randint(/my_secure_rng = secrets.SystemRandom() \\\n my_secure_rng.randrange(/g")
                cng_line=$(echo $cng_line | sed "s/random.randint(/MY_SECURE_RNG = SECRETS.SYSTEMRANDOM() \\\n MY_SECURE_RNG.RANDRANGE(/g")
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 54: detection of random.choice() function
        echo $line | grep -E -q -i "random.choice\(|choice\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]choice("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "secrets.choice("
                if [ $? -eq 0 ]; then
                    echo $line | grep -v -q "secrets\."
                    if [ $? -eq 0 ]; then
                        vuln="$vuln, KUF(CHOICE)"
                        rem_line=$(echo $rem_line | sed "s/random.choice(/secrets.choice(/g")
                        cng_line=$(echo $cng_line | sed "s/random.choice(/SECRETS.CHOICE(/g")
                        modify=1;
                        if [ $tp_kuf_s -eq 0 ]; then
                            if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                                let tp_kuf_s=tp_kuf_s+1;
                                taint_s=0;
                            else
                                if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                    let kufunc_s=kufunc_s+1;       
                                fi
                            fi
                        fi
                    fi
                fi

            fi
        fi



        #RULE 55: detection of jwt.process_jwt() function
        echo $line | grep -E -q -i "jwt.process_jwt\([a-zA-Z0-9]*[^,]\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]process_jwt("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "verify_jwt("
                if [ $? -eq 0 ]; then
                    token=$(echo $line | awk -F 'jwt.process_jwt\\(' '{print $2}' | awk -F  ')' '{print $1}')
                    vuln="$vuln, KUF(PROCESS_JWT)"
                    rem_line=$(echo $rem_line | sed "s/jwt.process_jwt($token/jwt.process_jwt($token, \"key\", algorithms=[\"HS512\"]/g" | sed "s/jwt.process_jwt( $token/jwt.process_jwt($token, \"key\", algorithms=[\"HS512\"]/g")
                    cng_line=$(echo $cng_line | sed "s/jwt.process_jwt($token/JWT.PROCESS_JWT($token, \"KEY\", ALGORITHMS=[\"HS512\"]/g" | sed "s/jwt.process_jwt( $token/JWT.PROCESS_JWT($token, \"KEY\", ALGORITHMS=[\"HS512\"]/g")
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi



        #RULE 56: detection of mktmp() function
        echo $line | grep -E -q -i "mktemp\(|\.mktemp\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]mktemp("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def mktemp("
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(MKTMP)"
                    rem_line=$(echo $rem_line | sed "s/mktemp(/TemporaryFile(/g")
                    cng_line=$(echo $cng_line | sed "s/mktemp(/TEMPORARYFILE(/g")
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi



        #RULE 57: detection of time.clock() function
        echo $line | grep -E -q -i "time.clock\(|clock\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]clock("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def clock("
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(CLOCK)"
                    rem_line=$(echo $rem_line | sed "s/clock(/perf_counter(/g")
                    cng_line=$(echo $cng_line | sed "s/clock(/PERF_COUNTER(/g")
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi



        #RULE 58: detection of pickle functions
        new_line46=$(echo $line | sed "s/import cPickle/ /g" | sed "s/import pickle/ /g" | sed "s/import [a-zA-Z0-9]cPickle/ /g" | sed "s/import _pickle/ /g" | sed "s/pickle.this/ /g" )
        echo $new_line46 | grep -E -q -i "pickle\.loads\(|pickle\.load\(|pickle\.dump\(|pickle\.dumps\(|pickle\.Unpickler\(|cPickle\.loads\(|cPickle\.load\(|cPickle\.dump\(|cPickle\.dumps\(|cPickle\.Unpickler\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]pickle"
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "[a-zA-Z0-9]cPickle"
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(PICKLE)"
                    rem_line=$(echo $rem_line | sed "s/pickle./pickle_secure./g" | sed "s/cPickle./pickle_secure./g" | sed "s/import pickle/import pickle_secure/g" | sed "s/import cPickle/import pickle_secure/g" )
                    cng_line=$(echo $cng_line | sed "s/pickle./PICKLE_SECURE./g" | sed "s/cPickle./PICKLE_SECURE./g" | sed "s/import pickle/IMPORT PICKLE_SECURE/g" | sed "s/import cPickle/IMPORT PICKLE_SECURE/g" )
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi


        #RULE 59: detection of xml.sax.make_parser() function
        echo $line | grep -E -q -i "xml.sax.make_parser\(|xml\.sax\."
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]xml\.sax\."
            if [ $? -eq 0 ]; then
                echo $line | grep -E -v -q -i "setFeature\(feature_external_ges, False\)|setFeature\(feature_external_ges,False\)"
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(XML_SAX)"
                    rem_line=$(echo $rem_line | sed "s/xml.sax.make_parser/defusedxml.sax.make_parser/g" )
                    cng_line=$(echo $cng_line | sed "s/xml.sax.make_parser/DEFUSEDXML.SAX.MAKE_PARSER/g" )
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi

        #RULE 60: detection of assert
        echo $line | grep -E -q -i "\bassert\b| \bassert\b"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]assert"
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "except AssertionError"
                if [ $? -eq 0 ]; then
                    vuln="$vuln, KUF(ASSERT)"
                    #last_char=$(echo "${line: -1}")
                    #if [ $name_os = "Darwin" ]; then  #MAC-OS system
                    #    rem_line=${line:0:$((${#line} - 1))}
                    #elif [ $name_os = "Linux" ]; then #LINUX system
                    #    rem_line=${line::-1}
                    #fi
                    rem_line="$rem_line \\n except AssertionError as msg: \\n print(msg)"
                    cng_line="$cng_line \\n EXCEPT ASSERTIONERROR AS MSG: \\n PRINT(MSG)"
                    #rem_line="$rem_line $last_char"
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi



        #RULE 61: detection of hashlib.new() function with a single param
        echo $line | grep -q -i "hashlib.new([^a-z]*[a-zA-Z0-9]*[^,][^a-Z]*)"
        if [ $? -eq 0 ]; then
            vuln="$vuln, KUF(HASHLIB_NEW_ONE_PARAM)"
            protocol=$(echo $line | awk -F 'hashlib.new\\(' '{print $2}' | awk -F '\\)' '{print $1}')
            rem_line=$(echo $rem_line | sed "s/hashlib.new( $protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new($protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new('$protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new(' $protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new( '$protocol/hashlib.new('sha512', usedforsecurity=True/g" | sed "s/hashlib.new( ' $protocol/hashlib.new('sha512', usedforsecurity=True/g")
            cng_line=$(echo $cng_line | sed "s/hashlib.new( $protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new($protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new('$protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new(' $protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new( '$protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g" | sed "s/hashlib.new( ' $protocol/HASHLIB.NEW('SHA512', USEDFORSECURITY=TRUE/g")
            modify=1;
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 62: detection of pbkdf2_hmac() function
        echo $line | grep -E -q -i "pbkdf2_hmac\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]pbkdf2_hmac("
            if [ $? -eq 0 ]; then
                protocol=$(echo $line | awk -F 'pbkdf2_hmac\\(' '{print $2}' | awk -F ',' '{print $1}')
                echo $protocol | grep -E -q -i "sha512|sha3_224|sha3_256|sha3_384|sha3_512" #whitelisting
                if [ $? -eq 1 ]; then #are used protocols different form the selected ones
                    vuln="$vuln, KUF(PBKDF2_HMAC)"
                    rem_line=$(echo $rem_line | sed "s/pbkdf2_hmac( $protocol/pbkdf2_hmac('sha512'/g" | sed "s/pbkdf2_hmac($protocol/pbkdf2_hmac('sha512'/g" | sed "s/pbkdf2_hmac('$protocol/pbkdf2_hmac('sha512/g" | sed "s/pbkdf2_hmac(' $protocol/pbkdf2_hmac('sha512/g" | sed "s/pbkdf2_hmac( '$protocol/pbkdf2_hmac('sha512/g" | sed "s/pbkdf2_hmac( ' $protocol/pbkdf2_hmac('sha512/g")
                    cng_line=$(echo $cng_line | sed "s/pbkdf2_hmac( $protocol/PBKDF2_HMAC('SHA512'/g" | sed "s/pbkdf2_hmac($protocol/PBKDF2_HMAC('SHA512'/g" | sed "s/pbkdf2_hmac('$protocol/PBKDF2_HMAC('SHA512/g" | sed "s/pbkdf2_hmac(' $protocol/PBKDF2_HMAC('SHA512/g" | sed "s/pbkdf2_hmac( '$protocol/PBKDF2_HMAC('SHA512/g" | sed "s/pbkdf2_hmac( ' $protocol/PBKDF2_HMAC('SHA512/g")
                    modify=1;
                    if [ $tp_kuf_s -eq 0 ]; then
                        if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            let tp_kuf_s=tp_kuf_s+1;
                            taint_s=0;
                        else
                            if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                                let kufunc_s=kufunc_s+1;       
                            fi
                        fi
                    fi
                fi
            fi
        fi



        #RULE 63: detection of parseUDPpacket() function
        echo $line | grep -E -q -i "parseUDPpacket\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]parseUDPpacket("
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(UDP)"
                rem_line=$(echo $rem_line | sed "s/parseUDPpacket(/parseTCPpacket(/g" | sed "s/parseUDPpacket(/parseTCPpacket(/g" )
                cng_line=$(echo $cng_line | sed "s/parseUDPpacket(/PARSETCPPACKET(/g" | sed "s/parseUDPpacket(/PARSETCPPACKET(/g" )
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 64: detection of os.system(...file.bin...) function
        echo $line | grep -E -q -i "os.system\([^a-z]*[a-z]*\.bin"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]os.system([^a-z]*[a-z]*\.bin"
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(SYSTEM_BIN)"
                rem_line=$(echo $rem_line | sed "s/.bin/.txt/g" )
                cng_line=$(echo $cng_line | sed "s/.bin/.TXT/g" )
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi



        #RULE 65: detection of exec() and os.system() function
        echo $line | grep -E -q -i "\(exec, \('import os;os.system\(|\(exec,\('import os;os.system\(|\(exec,\('import os ; os.system\(|\(exec, \('import os ; os.system\("
        if [ $? -eq 0 ]; then
            vuln="$vuln, KUF(EXEC_SYSTEM)"
            modify=2; #NOT MOD
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 66: detection of etree.ElementTree library
        echo $line | grep -q -i "etree.ElementTree as ET.*ET\."
        if [ $? -eq 0 ]; then
            vuln="$vuln, KUF(ET)"
            rem_line=$(echo $rem_line | sed "s/etree.ElementTree/defusedxml.ElementTree/g" )
            cng_line=$(echo $cng_line | sed "s/etree.ElementTree/DEFUSEDXML.ELEMENTTREE/g" )
            modify=1;
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 67: detection of GENERIC 'raisePrivilege() function() lowPrivilege()'
        echo $line | grep -q -i "raisePrivileges().*lowerPrivileges()"
        if [ $? -eq 0 ]; then
            vuln="$vuln, KUF(PRIVILEGE)"
            rem_line=$(echo $rem_line | sed "s/raisePrivileges()/ /g" | sed "s/lowerPrivileges()/ /g" )
            cng_line=$(echo $cng_line | sed "s/raisePrivileges()/ /g" | sed "s/lowerPrivileges()/ /g" )
            modify=1;
            if [ $tp_kuf_s -eq 0 ]; then
                if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    let tp_kuf_s=tp_kuf_s+1;
                    taint_s=0;
                else
                    if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                        let kufunc_s=kufunc_s+1;       
                    fi
                fi
            fi
        fi



        #RULE 68: detection of GENERIC 'requests.get(..., verify=False)'
        echo $line | grep -q "requests\..*(.*verify=False"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]requests\."
            if [ $? -eq 0 ]; then
                vuln="$vuln, KUF(VERIFY_FALSE)"
                rem_line=$(echo $rem_line | sed "s/verify=False/verify=True/g" | sed "s/verify = False/verify=True/g" |sed "s/verify=false/verify=True/g" | sed "s/verify = false/verify=True/g")
                cng_line=$(echo $cng_line | sed "s/verify=False/VERIFY=TRUE/g" | sed "s/verify = False/VERIFY=TRUE/g" |sed "s/verify=false/VERIFY=TRUE/g" | sed "s/verify = false/VERIFY=TRUE/g")
                modify=1;
                if [ $tp_kuf_s -eq 0 ]; then
                    if [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        let tp_kuf_s=tp_kuf_s+1;
                        taint_s=0;
                    else
                        if [ $kufunc_s -eq 0 ]; then #I count the single category occurence per snippet
                            let kufunc_s=kufunc_s+1;       
                        fi
                    fi
                fi
            fi
        fi






        ########            START CONFIGURATION PROBLEM        ########
        #RULE 69: detection of os.chmod() function
        echo $line | grep -E -q -i "os.chmod\(.*, 0000\)|os.chmod\(.*, 0o400\)|os.chmod\(.*, 128\)"
        if [ $? -eq 0 ]; then
            vuln="$vuln, CP(OS.CHMOD)"
            rem_line=$(echo $rem_line | sed "s/0000/600/g" | sed "s/0o400/600/g" | sed "s/128/600/g" )
            cng_line=$(echo $cng_line | sed "s/0000/600/g" | sed "s/0o400/600/g" | sed "s/128/600/g" )
            modify=1;
            if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                if [ $tp_kuf_cp_s -eq 0 ]; then
                    let tp_kuf_cp_s=tp_kuf_cp_s+1;
                    tp_kuf_s=0;
                fi
            elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                if [ $tp_cp_s -eq 0 ]; then
                    let tp_cp_s=tp_cp_s+1;
                    taint_s=0;
                fi
            elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                if [ $kuf_cp_s -eq 0 ]; then
                    let kuf_cp_s=kuf_cp_s+1;
                    kufunc_s=0;
                fi
            elif [ $confprob_s -eq 0 ]; then
                let confprob_s=confprob_s+1;
            fi
        fi



        #RULE 70: detection of response.set_cookie() with plaintext password
        new_line=$(echo $line | sed "s/def set_cookie()/ /g" | sed "s/set_cookie(__name__)/ /g" )
        echo $new_line | grep -E -q -i "\.set_cookie\(.*, [a-zA-Z0-9]*\)|set_cookie\(.*, [a-zA-Z0-9]*\)|\.set_cookie\([^a-z]*[a-zA-Z0-9]*[^a-z]*\)|set_cookie\([^a-z]*[a-zA-Z0-9]*[^a-z]*\)"
        if [ $? -eq 0 ]; then
            echo $new_line | grep -v -q -i "\.set_cookie()"
            if [ $? -eq 0 ]; then
                token=$(echo $line | awk -F 'set_cookie\\(' '{print $2}' | awk -F  ')' '{print $1}' )
                split_token=$(echo $line | awk -F  ',' '{print $2}' | awk -F  ')' '{print $1}')
                if [ -z "$split_token" ]; then
                    rem_line=$(echo $rem_line | sed "s/$token/$token, date/g" )
                    cng_line=$(echo $cng_line | sed "s/$token/$token, DATE/g" )
                else
                    rem_line=$(echo $rem_line | sed "s/$split_token/$split_token, date/g" )
                    cng_line=$(echo $cng_line | sed "s/$split_token/$split_token, DATE/g" )
                fi
                vuln="$vuln, CP(SET_COOKIE)"
                modify=1;
                if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                    if [ $tp_kuf_cp_s -eq 0 ]; then
                        let tp_kuf_cp_s=tp_kuf_cp_s+1;
                        tp_kuf_s=0;
                    fi
                elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    if [ $tp_cp_s -eq 0 ]; then
                        let tp_cp_s=tp_cp_s+1;
                        taint_s=0;
                    fi
                elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                    if [ $kuf_cp_s -eq 0 ]; then
                        let kuf_cp_s=kuf_cp_s+1;
                        kufunc_s=0;
                    fi
                elif [ $confprob_s -eq 0 ]; then
                    let confprob_s=confprob_s+1;
                fi
            fi
        fi



        #RULE 71: detection of 'ctx.check_hostname = False' AND 'ctx.verify_mode = ssl.CERT_NONE'
        echo $line | grep -q -i "ssl.create_default_context() .* ctx.verify_mode = ssl.CERT_NONE"
        if [ $? -eq 0 ]; then
            hostname=$(echo $line | awk -F 'check_hostname' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            cert=$(echo $line | awk -F 'verify_mode' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            vuln="$vuln, CP(SSL_DEFAULT_CONTEXT)"
            rem_line=$(echo $rem_line | sed "s/check_hostname = $hostname/check_hostname = True/g" | sed "s/check_hostname=$hostname/check_hostname=True/g" |  sed "s/check_hostname= $hostname/check_hostname= True/g" |  sed "s/check_hostname =$hostname/check_hostname =True/g" | sed "s/verify_mode = $cert/verify_mode = ssl.CERT_REQUIRED/g" | sed "s/verify_mode=$cert/verify_mode=ssl.CERT_REQUIRED/g" | sed "s/verify_mode= $cert/verify_mode= ssl.CERT_REQUIRED/g" | sed "s/verify_mode =$cert/verify_mode =ssl.CERT_REQUIRED/g")
            cng_line=$(echo $cng_line | sed "s/check_hostname = $hostname/CHECK_HOSTNAME = TRUE/g" | sed "s/check_hostname=$hostname/CHECK_HOSTNAME=TRUE/g" |  sed "s/check_hostname= $hostname/CHECK_HOSTNAME= TRUE/g" |  sed "s/check_hostname =$hostname/CHECK_HOSTNAME =TRUE/g" | sed "s/verify_mode = $cert/VERIFY_MODE = SSL.CERT_REQUIRED/g" | sed "s/verify_mode=$cert/VERIFY_MODE=SSL.CERT_REQUIRED/g" | sed "s/verify_mode= $cert/VERIFY_MODE= SSL.CERT_REQUIRED/g" | sed "s/verify_mode =$cert/VERIFY_MODE =SSL.CERT_REQUIRED/g")
            modify=1;
            if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                if [ $tp_kuf_cp_s -eq 0 ]; then
                    let tp_kuf_cp_s=tp_kuf_cp_s+1;
                    tp_kuf_s=0;
                fi
            elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                if [ $tp_cp_s -eq 0 ]; then
                    let tp_cp_s=tp_cp_s+1;
                    taint_s=0;
                fi
            elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                if [ $kuf_cp_s -eq 0 ]; then
                    let kuf_cp_s=kuf_cp_s+1;
                    kufunc_s=0;
                fi
            elif [ $confprob_s -eq 0 ]; then
                let confprob_s=confprob_s+1;
            fi
        fi



        #RULE 72: detection of 'ssl._create_unverified_context()'
        echo $line | grep -q -i "ssl._create_unverified_context()"
        if [ $? -eq 0 ]; then
            vuln="$vuln, CP(SSL_UNVERIFIED_CONTEXT)"
            rem_line=$(echo $rem_line | sed "s/ssl._create_unverified_context()/ssl._create_unverified_context() \\\n check_hostname = True \\\n verify_mode =ssl.CERT_REQUIRED/g" )
            cng_line=$(echo $cng_line | sed "s/ssl._create_unverified_context()/SSL._CREATE_UNVERIFIED_CONTEXT() \\\n CHECK_HOSTNAME = TRUE \\\n VERIFY_MODE =SSL.CERT_REQUIRED/g" )
            modify=1;
            if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                if [ $tp_kuf_cp_s -eq 0 ]; then
                    let tp_kuf_cp_s=tp_kuf_cp_s+1;
                    tp_kuf_s=0;
                fi
            elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                if [ $tp_cp_s -eq 0 ]; then
                    let tp_cp_s=tp_cp_s+1;
                    taint_s=0;
                fi
            elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                if [ $kuf_cp_s -eq 0 ]; then
                    let kuf_cp_s=kuf_cp_s+1;
                    kufunc_s=0;
                fi
            elif [ $confprob_s -eq 0 ]; then
                let confprob_s=confprob_s+1;
            fi
        fi



        #RULE 73: detection of 'ssl._create_stdlib_context()'
        echo $line | grep -q -i "ssl._create_stdlib_context()"
        if [ $? -eq 0 ]; then
            vuln="$vuln, CP(SSL_STDLIB_CONTEXT)"
            rem_line=$(echo $rem_line | sed "s/ssl._create_stdlib_context()/ssl._create_stdlib_context(ssl.PROTOCOL_TLS)/g")
            cng_line=$(echo $cng_line | sed "s/ssl._create_stdlib_context()/SSL._CREATE_STDLIB_CONTEXT(SSL.PROTOCOL_TLS)/g")
            modify=1;
            if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                if [ $tp_kuf_cp_s -eq 0 ]; then
                    let tp_kuf_cp_s=tp_kuf_cp_s+1;
                    tp_kuf_s=0;
                fi
            elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                if [ $tp_cp_s -eq 0 ]; then
                    let tp_cp_s=tp_cp_s+1;
                    taint_s=0;
                fi
            elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                if [ $kuf_cp_s -eq 0 ]; then
                    let kuf_cp_s=kuf_cp_s+1;
                    kufunc_s=0;
                fi
            elif [ $confprob_s -eq 0 ]; then
                let confprob_s=confprob_s+1;
            fi
        fi



        #RULE 74: detection of 'ssl.create_default_context()' AND'ctx.check_hostname = False'
        echo $line | grep -q -i "check_hostname = false"
        if [ $? -eq 0 ]; then
            hostname=$(echo $line | awk -F 'check_hostname' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            vuln="$vuln, CP(HOSTNAME_FALSE)"
            rem_line=$(echo $rem_line | sed "s/check_hostname = $hostname/check_hostname = True/g" | sed "s/check_hostname=$hostname/check_hostname=True/g" |  sed "s/check_hostname= $hostname/check_hostname= True/g" |  sed "s/check_hostname =$hostname/check_hostname =True/g" )
            cng_line=$(echo $cng_line | sed "s/check_hostname = $hostname/CHECK_HOSTNAME = TRUE/g" | sed "s/check_hostname=$hostname/CHECK_HOSTNAME=TRUE/g" |  sed "s/check_hostname= $hostname/CHECK_HOSTNAME= TRUE/g" |  sed "s/check_hostname =$hostname/CHECK_HOSTNAME =TRUE/g" )
            modify=1;
            if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                if [ $tp_kuf_cp_s -eq 0 ]; then
                    let tp_kuf_cp_s=tp_kuf_cp_s+1;
                    tp_kuf_s=0;
                fi
            elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                if [ $tp_cp_s -eq 0 ]; then
                    let tp_cp_s=tp_cp_s+1;
                    taint_s=0;
                fi
            elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                if [ $kuf_cp_s -eq 0 ]; then
                    let kuf_cp_s=kuf_cp_s+1;
                    kufunc_s=0;
                fi
            elif [ $confprob_s -eq 0 ]; then
                let confprob_s=confprob_s+1;
            fi
        fi



        #RULE 75: detection of SSL.TLSv1_2_METHOD
        echo $line | grep -q -i "SSL.TLSv1_2_METHOD"
        if [ $? -eq 0 ]; then
            vuln="$vuln, CP(SSL.TLSv1_2_METHOD)"
            #select the higher version of SSL
            rem_line=$(echo $rem_line | sed "s/SSL.TLSv1_2_METHOD/ssl.PROTOCOL_TLS/g" | sed "s/ssl.TLSv1_2_METHOD/ssl.PROTOCOL_TLS/g")
            cng_line=$(echo $cng_line | sed "s/SSL.TLSv1_2_METHOD/SSL.PROTOCOL_TLS/g" | sed "s/ssl.TLSv1_2_METHOD/SSL.PROTOCOL_TLS/g")
            modify=1;
            if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                if [ $tp_kuf_cp_s -eq 0 ]; then
                    let tp_kuf_cp_s=tp_kuf_cp_s+1;
                    tp_kuf_s=0;
                fi
            elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                if [ $tp_cp_s -eq 0 ]; then
                    let tp_cp_s=tp_cp_s+1;
                    taint_s=0;
                fi
            elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                if [ $kuf_cp_s -eq 0 ]; then
                    let kuf_cp_s=kuf_cp_s+1;
                    kufunc_s=0;
                fi
            elif [ $confprob_s -eq 0 ]; then
                let confprob_s=confprob_s+1;
            fi
        fi



        #RULE 76: detection of urandom() with value less than 64
        echo $line | grep -E -q -i "urandom\(([0-9]\)|6[0-3]\))"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q -i "[a-zA-Z0-9]urandom"
            if [ $? -eq 0 ]; then
                value=$(echo $line | awk -F 'urandom\\(' '{print $2}' | awk -F '\\)' '{print $1}')
                vuln="$vuln, CP(URANDOM)"
                rem_line=$(echo $rem_line | sed "s/urandom($value)/urandom(64)/g" | sed "s/urandom( $value )/urandom(64)/g" | sed "s/urandom( $value)/urandom(64)/g" | sed "s/urandom($value )/urandom(64)/g")
                cng_line=$(echo $cng_line | sed "s/urandom($value)/URANDOM(64)/g" | sed "s/urandom( $value )/URANDOM(64)/g" | sed "s/urandom( $value)/URANDOM(64)/g" | sed "s/urandom($value )/URANDOM(64)/g")
                modify=1;
                if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                    if [ $tp_kuf_cp_s -eq 0 ]; then
                        let tp_kuf_cp_s=tp_kuf_cp_s+1;
                        tp_kuf_s=0;
                    fi
                elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    if [ $tp_cp_s -eq 0 ]; then
                        let tp_cp_s=tp_cp_s+1;
                        taint_s=0;
                    fi
                elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                    if [ $kuf_cp_s -eq 0 ]; then
                        let kuf_cp_s=kuf_cp_s+1;
                        kufunc_s=0;
                    fi
                elif [ $confprob_s -eq 0 ]; then
                    let confprob_s=confprob_s+1;
                fi
            fi
        fi



        #RULE 77: detection of 'key_size' less than 2048
        echo $line | grep -E -q -i "key_size=([1-9] |[1-1][0-9][0-9] |[1-1][0-9][0-9][0-9] |204[0-7] )|key_size=([1-9]\\\n |[1-1][0-9][0-9]\\\n |[1-1][0-9][0-9][0-9]\\\n |204[0-7]\\\n )"
        if [ $? -eq 0 ]; then
            value=$(echo $line | awk -F 'key_size' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            vuln="$vuln, CP(KEY_SIZE)"
            rem_line=$(echo $rem_line | sed "s/key_size=$value/key_size=2048/g")
            cng_line=$(echo $cng_line | sed "s/key_size=$value/KEY_SIZE=2048/g")
            modify=1;
            if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                if [ $tp_kuf_cp_s -eq 0 ]; then
                    let tp_kuf_cp_s=tp_kuf_cp_s+1;
                    tp_kuf_s=0;
                fi
            elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                if [ $tp_cp_s -eq 0 ]; then
                    let tp_cp_s=tp_cp_s+1;
                    taint_s=0;
                fi
            elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                if [ $kuf_cp_s -eq 0 ]; then
                    let kuf_cp_s=kuf_cp_s+1;
                    kufunc_s=0;
                fi
            elif [ $confprob_s -eq 0 ]; then
                let confprob_s=confprob_s+1;
            fi
        fi



        #RULE 78: detection of 'jwt.decode(..., verify = False)'
        echo $line | grep -E -q -i "jwt.decode\(.*verify = False|jwt.decode\(.*verify=False"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]decode("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "([a-zA-Z0-9]verify = False"
                if [ $? -eq 0 ]; then
                    token=$(echo $line | awk -F 'decode\\(' '{print $2}' | awk -F  ',' '{print $1}')
                    vuln="$vuln, CP(JWT_VERIFY_FALSE1)"
                    rem_line=$(echo $rem_line | sed "s/jwt.decode(.*verify = False)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify=False)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify=false)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify = false)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g")
                    cng_line=$(echo $cng_line | sed "s/jwt.decode(.*verify = False)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify=False)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify=false)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*verify = false)/JWT.DECODE($token, \"KEY\", ALGORITMHS=[\"HS512\"])/g")
                    modify=1;
                    if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                        if [ $tp_kuf_cp_s -eq 0 ]; then
                            let tp_kuf_cp_s=tp_kuf_cp_s+1;
                            tp_kuf_s=0;
                        fi
                    elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        if [ $tp_cp_s -eq 0 ]; then
                            let tp_cp_s=tp_cp_s+1;
                            taint_s=0;
                        fi
                    elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                        if [ $kuf_cp_s -eq 0 ]; then
                            let kuf_cp_s=kuf_cp_s+1;
                            kufunc_s=0;
                        fi
                    elif [ $confprob_s -eq 0 ]; then
                        let confprob_s=confprob_s+1;
                    fi
                fi
            fi
        fi



        #RULE 79: detection of 'jwt.decode(token)'
        echo $line | grep -E -q -i "jwt.decode\([a-zA-Z0-9]*\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]decode("
            if [ $? -eq 0 ]; then
                token=$(echo $line | awk -F 'decode\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                vuln="$vuln, CP(JWT_VERIFY_FALSE21)"
                rem_line=$(echo $rem_line | sed "s/jwt.decode(.*)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/jwt.decode($token, \"key\", algorithms=[\"HS512\"])/g")
                cng_line=$(echo $cng_line | sed "s/jwt.decode(.*)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g" | sed "s/jwt.decode(.*)/JWT.DECODE($token, \"KEY\", ALGORITHMS=[\"HS512\"])/g")
                modify=1;
                if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                    if [ $tp_kuf_cp_s -eq 0 ]; then
                        let tp_kuf_cp_s=tp_kuf_cp_s+1;
                        tp_kuf_s=0;
                    fi
                elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    if [ $tp_cp_s -eq 0 ]; then
                        let tp_cp_s=tp_cp_s+1;
                        taint_s=0;
                    fi
                elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                    if [ $kuf_cp_s -eq 0 ]; then
                        let kuf_cp_s=kuf_cp_s+1;
                        kufunc_s=0;
                    fi
                elif [ $confprob_s -eq 0 ]; then
                    let confprob_s=confprob_s+1;
                fi
            fi
        fi



        #RULE 80: detection of 'jwt.decode(token, key, options={\"verify_signature\": False}..)'
        echo $line | grep -q -i "jwt.decode(.*, options={[^a-z]*verify_signature[^a-z]* False"
        if [ $? -eq 0 ]; then
            token=$(echo $line | awk -F 'decode\\(' '{print $2}' | awk -F  ',' '{print $1}')
            key=$(echo $line | awk -F 'decode\\(' '{print $2}' | awk -F  ',' '{print $2}' | awk -F  ',' '{print $1}')
            vuln="$vuln, CP(JWT_VERIFY_SIGNATURE_FALSE)"
            rem_line=$(echo $rem_line | sed "s/jwt.decode(.*options=.*: False})/jwt.decode($token, \"$key\", algorithms=[\"HS512\"])/g" )
            cng_line=$(echo $cng_line | sed "s/jwt.decode(.*options=.*: False})/JWT.DECODE($token, \"$key\", ALGORITHMS=[\"HS512\"])/g" )
            modify=1;
            if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                if [ $tp_kuf_cp_s -eq 0 ]; then
                    let tp_kuf_cp_s=tp_kuf_cp_s+1;
                    tp_kuf_s=0;
                fi
            elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                if [ $tp_cp_s -eq 0 ]; then
                    let tp_cp_s=tp_cp_s+1;
                    taint_s=0;
                fi
            elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                if [ $kuf_cp_s -eq 0 ]; then
                    let kuf_cp_s=kuf_cp_s+1;
                    kufunc_s=0;
                fi
            elif [ $confprob_s -eq 0 ]; then
                let confprob_s=confprob_s+1;
            fi
        fi





        #RULE 81: detection of 's.bind(('0.0.0.0', ...))'
        echo $line | grep -P -q -i "\.bind\(\(.*0.0.0.0.*?\)\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]bind\(\('0.0.0.0',.*\)\)"
            if [ $? -eq 0 ]; then
                vuln="$vuln, CP(BIND_0000)"
                rem_line=$(echo $rem_line | sed "s/0.0.0.0/84.68.10.12/g" )
                cng_line=$(echo $cng_line | sed "s/0.0.0.0/84.68.10.12/g" )
                modify=1;
                if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                    if [ $tp_kuf_cp_s -eq 0 ]; then
                        let tp_kuf_cp_s=tp_kuf_cp_s+1;
                        tp_kuf_s=0;
                    fi
                elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    if [ $tp_cp_s -eq 0 ]; then
                        let tp_cp_s=tp_cp_s+1;
                        taint_s=0;
                    fi
                elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                    if [ $kuf_cp_s -eq 0 ]; then
                        let kuf_cp_s=kuf_cp_s+1;
                        kufunc_s=0;
                    fi
                elif [ $confprob_s -eq 0 ]; then
                    let confprob_s=confprob_s+1;
                fi
            fi
        fi



        #RULE 82: detection of 'etree.XMLParser(resolve_entities=True)' AND 'XMLParser(resolve_entities=True)' OR 'etree.XMLParser()' AND 'XMLParser()'
        echo $line | grep -E -q -i "etree.XMLParser\(resolve_entities=True\)|XMLParser\(resolve_entities=True\)|XMLParser\(\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]XMLParser("
            if [ $? -eq 0 ]; then
                entity=$(echo $line | awk -F 'XMLParser\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                vuln="$vuln, CP(XMLPARSER_ENT_TRUE)"
                rem_line=$(echo $rem_line | sed "s/XMLParser($entity)/XMLParser(resolve_entities=False, no_network=True)/g" | sed "s/XMLParser( $entity )/XMLParser(resolve_entities=False, no_network=True)/g" )
                cng_line=$(echo $cng_line | sed "s/XMLParser($entity)/XMLPARSER(RESOLVE_ENTITIES=FALSE, NO_NETWORK=TRUE)/g" | sed "s/XMLParser( $entity )/XMLPARSER(RESOLVE_ENTITIES=FALSE, NO_NETWORK=TRUE)/g" )
                modify=1;
                if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                    if [ $tp_kuf_cp_s -eq 0 ]; then
                        let tp_kuf_cp_s=tp_kuf_cp_s+1;
                        tp_kuf_s=0;
                    fi
                elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    if [ $tp_cp_s -eq 0 ]; then
                        let tp_cp_s=tp_cp_s+1;
                        taint_s=0;
                    fi
                elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                    if [ $kuf_cp_s -eq 0 ]; then
                        let kuf_cp_s=kuf_cp_s+1;
                        kufunc_s=0;
                    fi
                elif [ $confprob_s -eq 0 ]; then
                    let confprob_s=confprob_s+1;
                fi
            fi
        fi



        #RULE 83: detection of 'etree.XSLTAccessControl(read_network=True...)' AND 'XSLTAccessControl(read_network=True...)'
        echo $line | grep -E -q -i "etree.XSLTAccessControl\(.*read_network=True|XSLTAccessControl\(.*read_network=True|XSLTAccessControl\(.*write_network=True"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]XSLTAccessControl(.*read_network=True"
            if [ $? -eq 0 ]; then
                code_before=$(echo $line | awk -F 'XSLTAccessControl\\(' '{print $1}')
                parameters=$(echo $line | awk -F 'XSLTAccessControl\\(' '{print $2}' | awk -F  '\\)' '{print $1}')
                vuln="$vuln, CP(XSLT_NETWORK_TRUE)"
                rem_line=$(echo $rem_line | sed "s/$code_before"XSLTAccessControl"($parameters/parser = etree.XMLParser(resolve_entities=False/g" | sed "s/$code_before"XSLTAccessControl"( $parameters/parser = etree.XMLParser(resolve_entities=False/g" )
                cng_line=$(echo $cng_line | sed "s/$code_before"XSLTAccessControl"($parameters/PARSER = ETREE.XMLPARSER(RESOLVE_ENTITIES=FALSE/g" | sed "s/$code_before"XSLTAccessControl"( $parameters/PARSER = ETREE.XMLPARSER(RESOLVE_ENTITIES=FALSE/g" )
                echo $line | grep -E -q -i "access_control"
                if [ $? -eq 0 ]; then
                    name_var=$(echo $line | awk -F 'access_control' '{print $2}'| awk -F  '\\)' '{print $1}')
                    first_char=${name_var::1}
                    if [ $first_char == "=" ]; then
                        name_var="${name_var:1}"
                    fi
                fi
                rem_line=$(echo $rem_line | sed "s/XMLParser(resolve_entities=False)/XMLParser(resolve_entities=False) \\\n $name_var = etree.XSLTAccessControl.DENY_ALL/g" | sed "s/XMLParser(resolve_entities=False )/XMLParser(resolve_entities=False) \\\n $name_var = etree.XSLTAccessControl.DENY_ALL/g" )
                cng_line=$(echo $cng_line | sed "s/XMLParser(resolve_entities=False)/XMLPARSER(RESOLVE_ENTITIES=FALSE) \\\n $name_var = ETREE.XSLTACCESSCONTROL.DENY_ALL/g" | sed "s/XMLParser(resolve_entities=False )/XMLPARSER(RESOLVE_ENTITIES=FALSE) \\\n $name_var = ETREE.XSLTACCESSCONTROL.DENY_ALL/g" )
                modify=1;
                if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                    if [ $tp_kuf_cp_s -eq 0 ]; then
                        let tp_kuf_cp_s=tp_kuf_cp_s+1;
                        tp_kuf_s=0;
                    fi
                elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    if [ $tp_cp_s -eq 0 ]; then
                        let tp_cp_s=tp_cp_s+1;
                        taint_s=0;
                    fi
                elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                    if [ $kuf_cp_s -eq 0 ]; then
                        let kuf_cp_s=kuf_cp_s+1;
                        kufunc_s=0;
                    fi
                elif [ $confprob_s -eq 0 ]; then
                    let confprob_s=confprob_s+1;
                fi
            fi
        fi



        #RULE 84: detection of 'os.chmod(file.bin)'
        echo $line | grep -E -q -i "os.chmod\([^a-z]*[a-z]*\.bin"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]os.chmod([^a-z]*[a-z]*\.bin"
            if [ $? -eq 0 ]; then
                vuln="$vuln, CP(XSLT_NETWORK_TRUE)"
                rem_line=$(echo $rem_line | sed "s/.bin/.txt/g" )
                cng_line=$(echo $cng_line | sed "s/.bin/.TXT/g" )
                modify=1;
                if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                    if [ $tp_kuf_cp_s -eq 0 ]; then
                        let tp_kuf_cp_s=tp_kuf_cp_s+1;
                        tp_kuf_s=0;
                    fi
                elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                    if [ $tp_cp_s -eq 0 ]; then
                        let tp_cp_s=tp_cp_s+1;
                        taint_s=0;
                    fi
                elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                    if [ $kuf_cp_s -eq 0 ]; then
                        let kuf_cp_s=kuf_cp_s+1;
                        kufunc_s=0;
                    fi
                elif [ $confprob_s -eq 0 ]; then
                    let confprob_s=confprob_s+1;
                fi
            fi
        fi



        #RULE 85: detection of INCREMENT
        echo $line | grep -q -i "while .<"
        if [ $? -eq 0 ]; then
            var=$(echo $line | awk -F "while" '{print $2}' | awk -F ":" '{print $1}'| awk -F "<" '{print $1}'| awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "<" ]; then
                    var=$(echo $line | awk -F "while" '{print $1}' | awk '{print $(NF-1)}')                    
                fi 
                fin_param=$(echo $line | awk -F "while" '{print $2}' |   awk -F "<" '{print $2}'| awk -F ":" '{print $1}' | awk '{print $NF}')
                
                ####	CHECK
                echo $line | grep -E -v -q "$var\+\+|$var \+\+|$var\+=1|$var=$var\+1|$var = $var \+ 1|$var= $var \+ 1|$var=$var \+ 1|$var=$var\+ 1|$var =$var \+ 1|$var =$var\+ 1"
                if [ $? -eq 0 ]; then
                    vuln="$vuln, CP(INCREMENT)"
                    rem_line=$(echo $rem_line | sed "s/while $var<n:/while $var<n: \\\n $var++/g" )
                    cng_line=$(echo $cng_line | sed "s/while $var<n:/WHILE $var<N: \\\n $var++/g" )
                    modify=1;
                    if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                        if [ $tp_kuf_cp_s -eq 0 ]; then
                            let tp_kuf_cp_s=tp_kuf_cp_s+1;
                            tp_kuf_s=0;
                        fi
                    elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        if [ $tp_cp_s -eq 0 ]; then
                            let tp_cp_s=tp_cp_s+1;
                            taint_s=0;
                        fi
                    elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                        if [ $kuf_cp_s -eq 0 ]; then
                            let kuf_cp_s=kuf_cp_s+1;
                            kufunc_s=0;
                        fi
                    elif [ $confprob_s -eq 0 ]; then
                        let confprob_s=confprob_s+1;
                    fi
                fi
            fi  
        fi



        #RULE 86: detection of lock
        echo $line | grep -E -q -i "= Lock\(\).*\.acquire\(\)|=Lock\(\).*\.acquire\(\)"
        if [ $? -eq 0 ]; then
            var=$(echo $line | awk -F "Lock\\\(" '{print $1}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "Lock\\\(" '{print $1}' | awk '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi 
                
                ####	CHECK
                echo $line | grep -v -q "if $var.locked()"
                if [ $? -eq 0 ]; then
                    vuln="$vuln, CP(LOCK)"
                    rem_line=$(echo $rem_line | sed "s/$var = Lock().*$var.acquire()/lock = Lock() \\\n if $var.locked(): \\\n $var.acquire()/g" )
                    cng_line=$(echo $cng_line | sed "s/$var = Lock().*$var.acquire()/LOCK = LOCK() \\\n IF $var.LOCKED(): \\\n $var.ACQUIRE()/g" )
                    modify=1;
                    if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                        if [ $tp_kuf_cp_s -eq 0 ]; then
                            let tp_kuf_cp_s=tp_kuf_cp_s+1;
                            tp_kuf_s=0;
                        fi
                    elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                        if [ $tp_cp_s -eq 0 ]; then
                            let tp_cp_s=tp_cp_s+1;
                            taint_s=0;
                        fi
                    elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                        if [ $kuf_cp_s -eq 0 ]; then
                            let kuf_cp_s=kuf_cp_s+1;
                            kufunc_s=0;
                        fi
                    elif [ $confprob_s -eq 0 ]; then
                        let confprob_s=confprob_s+1;
                    fi
                fi
            fi
        fi



        #RULE 87: detection of with open ... as value: ... value.read()
        num_occ=$(echo $line | awk -F "with open\\\(" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        det_var=0;
        while [ $i -le $num_occ ]; do
            let det_var=i+1;
            var=$(echo $line | awk -F "with open\\\(" -v i="$det_var" '{print $i}' | awk -F "," '{print $1}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else 

                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g"  | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" |  sed "s/\" $var/ /g" |  sed "s/'$var'/ /g"  | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g")
                echo $line | grep -q -i "with open(.*as.*\.read("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if os.path.isfile\($var\)|if os.path.isfile\( $var \)|if os.path.isfile\( $var\)|if os.path.isfile\($var \)"
                    if [ $? -eq 0 ]; then
                        vuln="$vuln, CP(READ_FILE)"
                        modify=2; #NOT MOD
                        if [ $taint_s -ne 0 ] && [ $kufunc_s -ne 0 ]; then #If the snippet is TP_KUF_CP vulnerable
                            if [ $tp_kuf_cp_s -eq 0 ]; then
                                let tp_kuf_cp_s=tp_kuf_cp_s+1;
                                tp_kuf_s=0;
                            fi
                        elif [ $taint_s -ne 0 ]; then #If the snippet is also TP vulnerable 
                            if [ $tp_cp_s -eq 0 ]; then
                                let tp_cp_s=tp_cp_s+1;
                                taint_s=0;
                            fi
                        elif [ $kufunc_s -ne 0 ]; then #If the snippet is also KUF vulnerable 
                            if [ $kuf_cp_s -eq 0 ]; then
                                let kuf_cp_s=kuf_cp_s+1;
                                kufunc_s=0;
                            fi
                        elif [ $confprob_s -eq 0 ]; then
                            let confprob_s=confprob_s+1;
                        fi
                    fi
                fi

            fi
            let i=i+1;
            let check=num_occ+1;
        done




        ##################          ADJUSTING DATA         #######################
        line=$(echo $line | sed "s/PRODUCT_SYMBOL/*/g")
        rem_line=$(echo $rem_line | sed "s/PRODUCT_SYMBOL/*/g")
        cng_line=$(echo $cng_line | sed "s/PRODUCT_SYMBOL/*/g")



        ##################          FINAL CHECK         #######################
        if [[ ! $vuln ]]; then
            { echo "Safe Code"; echo ":"; echo "$line"; } | tr "\n" " " >> $2;
            echo -e "\n" >> $2;
            { echo "Safe Code"; echo ":"; echo "$line"; } | tr "\n" " " >> $3;
            echo -e "\n" >> $3;
            #{ echo "Safe Code"; echo ":"; echo "$line"; } | tr "\n" " " >> $4;
            #echo -e "\n" >> $4;
            let dimtestset=dimtestset+1;
        else
            if [ $modify -eq 1 ]; then #vuln AND rem
                { echo "[!]"; echo $vuln; echo ":"; echo "$line"; } | tr "\n" " " >> $2;
                echo -e "\n" >> $2;
                { echo "[MOD]"; echo $vuln; echo ":"; echo "$rem_line"; } | tr "\n" " " >> $3;
                echo -e "\n" >> $3;
                { echo "[VULN]"; echo $vuln; echo ":"; echo "$line"; } | tr "\n" " " >> $4;
                echo -e "\n" >> $4;
                { echo "[SAFE]"; echo $vuln; echo ":"; echo "$cng_line"; } | tr "\n" " " >> $4;
                echo -e "\n\n\n" >> $4;
                let countvuln=countvuln+1;
                let dimtestset=dimtestset+1;
                let contMod=contMod+1;
            elif [ $modify -eq 2 ] || [ $modify -eq 0 ]; then #vuln BUT NOT rem
                { echo "[!]"; echo $vuln; echo ":"; echo "$line"; } | tr "\n" " " >> $2;
                echo -e "\n" >> $2;
                { echo "[NOT_MOD]"; echo $vuln; echo ":"; echo "$rem_line"; } | tr "\n" " " >> $3;
                echo -e "\n" >> $3;
                { echo "[VULN]"; echo $vuln; echo ":"; echo "$line"; } | tr "\n" " " >> $4;
                echo -e "\n" >> $4;
                { echo "[NOT_SAFE]"; echo $vuln; echo ":"; echo "$cng_line"; } | tr "\n" " " >> $4;
                echo -e "\n\n\n" >> $4;
                let countvuln=countvuln+1;
                let dimtestset=dimtestset+1;
                let contNoMod=contNoMod+1;
            fi
        fi



        ##################          FINAL COUNT VULNERABILITIES         #######################
        if [ $tp_kuf_cp_s -ne 0 ]; then
            let tp_kuf_cp=tp_kuf_cp+1;
        elif [ $taint_s -ne 0 ]; then
            let taint=taint+1;
        elif [ $kufunc_s -ne 0 ]; then
            let kufunc=kufunc+1;
        elif [ $confprob_s -ne 0 ]; then
            let confprob=confprob+1;
        elif [ $tp_kuf_s -ne 0 ]; then
            let tp_kuf=tp_kuf+1;
        elif [ $tp_cp_s -ne 0 ]; then
            let tp_cp=tp_cp+1;
        elif [ $kuf_cp_s -ne 0 ]; then
            let kuf_cp=kuf_cp+1;
        fi

        
    fi

done < "$input"

##################          RULES COMPUTATIONAL TIME         ########################### 
end=$(date +%s.%N)   
if [ $name_os = "Darwin" ]; then  #MAC-OS system
    runtime=$( echo "$end - $start" | bc -l )
elif [ $name_os = "Linux" ]; then #LINUX system 
    runtime=$(python -c "print(${end} - ${start})")
fi



##################          RESULTS ON FILE         ########################### 
#DET file
echo -e "\n\n\n" >> $2;
echo -e "======>    DATASET SIZE   <======\n" >> $2;
{ echo "#DimTestSet:"; echo $dimtestset; } | tr "\n" " " >> $2;
echo -e "\n\n\n" >> $2;

echo -e "======>    FINAL RESULTS DETECTION   <======\n" >> $2;
{ echo "#TotalVulnerabilities:"; echo $countvuln; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "#SafeVuln:";  awk -v var1=$dimtestset -v var2=$countvuln 'BEGIN { if(var1!=0) { print  ( var1 - var2 )  } else {print 0} }'; } | tr "\n" " "  >> $2;
echo -e "\n" >> $2;
{ echo "Vulnerability Rate:"; awk -v var1=$countvuln -v var2=$dimtestset 'BEGIN { if(var2!=0) { print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " "  >> $2;
echo -e "\n\n" >> $2;

{ echo "#TP per snippet:"; echo $taint; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "#KUF per snippet:"; echo $kufunc; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "#CP per snippet:"; echo $confprob; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "#TP_KUF per snippet:"; echo $tp_kuf; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "#TP_CP per snippet:"; echo $tp_cp; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "#KUF_CP per snippet:"; echo $kuf_cp; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "#TP_KUF_CP per snippet:"; echo $tp_kuf_cp; } | tr "\n" " " >> $2;
echo -e "\n\n\n" >> $2;

echo -e "======>    EXECUTION TIME   <======\n" >> $2;
{ echo "Runtime:"; echo $runtime; echo "s"; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "Runtime per snippet:"; awk -v var1=$runtime -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) } else {print 0} }'; echo "s"; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;

#REM file
echo -e "\n\n\n" >> $3;
echo -e "======>    DATASET SIZE   <======\n" >> $3;
{ echo "#DimTestSet:"; echo $dimtestset; } | tr "\n" " " >> $3;
echo -e "\n\n\n" >> $3;

echo -e "======>    FINAL RESULTS REMEDIATION   <======\n" >> $3;
{ echo "#DetectedVuln:"; echo $countvuln; } | tr "\n" " " >> $3;
echo -e "\n" >> $3;
{ echo "#Remediated:"; echo $contMod; } | tr "\n" " "  >> $3;
echo -e "\n" >> $3;
{ echo "#NotRemediated:"; echo $contNoMod; } | tr "\n" " "  >> $3;
echo -e "\n" >> $3;
{ echo "Remediated Rate:"; awk -v var1=$contMod -v var2=$countvuln 'BEGIN { if(var2!=0) { print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " " >> $3;
echo -e "\n" >> $3;
{ echo "Not Remediated Rate:"; awk -v var1=$contNoMod -v var2=$countvuln 'BEGIN { if(var2!=0) {  print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " " >> $3;
echo -e "\n\n\n" >> $3;

echo -e "======>    EXECUTION TIME   <======\n" >> $3;
{ echo "Runtime:"; echo $runtime; echo "s"; } | tr "\n" " " >> $3;
echo -e "\n" >> $3;
{ echo "Runtime per snippet:"; awk -v var1=$runtime -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) } }'; echo "s"; } | tr "\n" " " >> $3;
echo -e "\n" >> $3;

#CNG file
echo -e "\n\n\n" >> $4;
echo -e "======>    SUMMARY   <======\n" >> $4;
{ echo "#Vuln:"; echo $countvuln; } | tr "\n" " " >> $4;
echo -e "\n" >> $4;
{ echo "#Safe:"; echo $contMod; } | tr "\n" " " >> $4;
echo -e "\n" >> $4;
{ echo "#NotSafe:"; echo $contNoMod; } | tr "\n" " " >> $4;
echo -e "\n" >> $4;


##################          RESULTS ON PROMPT         ########################### 
echo -e "\n";
echo -e "======>    DATASET SIZE   <======\n";
{ echo "#DimTestSet:"; echo $dimtestset; } | tr "\n" " ";
echo -e "\n\n\n";

echo -e "======>    FINAL RESULTS DETECTION   <======\n";
{ echo "#TotalVulnerabilities:"; echo $countvuln; } | tr "\n" " ";
echo -e "\n";
{ echo "#SafeVuln:";  awk -v var1=$dimtestset -v var2=$countvuln 'BEGIN { if(var1!=0) { print  ( var1 - var2 )  } else {print 0} }'; } | tr "\n" " ";
echo -e "\n";
{ echo "Vulnerability Rate:"; awk -v var1=$countvuln -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " ";
echo -e "\n\n";

{ echo "#TP per snippet:"; echo $taint; } | tr "\n" " ";
echo -e "\n";
{ echo "#KUF per snippet:"; echo $kufunc; } | tr "\n" " ";
echo -e "\n";
{ echo "#CP per snippet:"; echo $confprob; } | tr "\n" " ";
echo -e "\n";
{ echo "#TP_KUF per snippet:"; echo $tp_kuf; } | tr "\n" " ";
echo -e "\n";
{ echo "#TP_CP per snippet:"; echo $tp_cp; } | tr "\n" " ";
echo -e "\n";
{ echo "#KUF_CP per snippet:"; echo $kuf_cp; } | tr "\n" " ";
echo -e "\n";
{ echo "#TP_KUF_CP per snippet:"; echo $tp_kuf_cp; } | tr "\n" " ";
echo -e "\n\n\n";

echo -e "======>    FINAL RESULTS REMEDIATION   <======\n";
{ echo "#Remediated:"; echo $contMod; } | tr "\n" " ";
echo -e "\n";
{ echo "#NotRemediated:"; echo $contNoMod; } | tr "\n" " ";
echo -e "\n";
{ echo "Remediated Rate:"; awk -v var1=$contMod -v var2=$countvuln 'BEGIN { if(var2!=0) { print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " ";
echo -e "\n";
{ echo "Not Remediated Rate:"; awk -v var1=$contNoMod -v var2=$countvuln 'BEGIN { if(var2!=0) { print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " ";
echo -e "\n\n\n";

echo -e "======>    EXECUTION TIME   <======\n";
{ echo "Runtime:"; echo $runtime; echo "s"; } | tr "\n" " ";
echo -e "\n";
{ echo "Runtime per snippet:"; awk -v var1=$runtime -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) } else {print 0} }'; echo "s"; } | tr "\n" " ";
echo -e "\n";