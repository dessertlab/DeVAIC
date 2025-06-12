#!/bin/bash
start=$(date +%s.%N)

input=$1

#tool for DETECTION of OWASP top 10 categories

#DET file intro
echo -e "==================>      SNIPPETS DETECTED      <========================" > $2  
echo -e "|                                                                       |" >> $2
echo -e "|           (!) VULN CODE : Vulnerable code snippets detected           |" >> $2
echo -e "|           ==> SAFE CODE : Safe code snippet                           |" >> $2
echo -e "|                                                                       |" >> $2
echo -e "|                 [XXX s] : Execution Time per snippet                  |" >> $2
echo -e "|                                                                       |" >> $2
echo -e "=========================================================================\n" >> $2



countvuln=0; 
dimtestset=0;
contNoMod=0;
contMod=0;

name_os=$(uname) #OS-system

# VARIABLES FOR OWASP MAPPING - GLOBAL COUNTERS
inj_count=0;  # Injection
crypto_count=0; # Cryptografic Failures
sec_mis_count=0; # Security Misconfiguration
bac_count=0;  # Broken Access Control
id_auth_count=0; # Identification and Authentication Failures
sec_log_count=0; # Secuirty Logging and Monitoring Failures 
ins_des_count=0; # Insecure Design
ssrf_count=0; # SSRF
soft_data_count=0; # Software and Data Integrity Failures

while IFS= read -r line; do

    #initial timestamp all rules for snippet
    start_snippet=$(date +%s.%N)

    if [ ! -z "$line" ]; then
        num_occ=0;
        pass=0;
        var=
        vuln=

        # VARIABLES FOR OWASP MAPPING  
        inj=0;  # Injection
        crypto=0; # Cryptografic Failures
        sec_mis=0; # Security Misconfiguration
        bac=0;  # Broken Access Control
        id_auth=0; # Identification and Authentication Failures
        sec_log=0; # Secuirty Logging and Monitoring Failures 
        ins_des=0; # Insecure Design
        ssrf=0; # SSRF
        soft_data=0; # Software and Data Integrity Failures


        #RULE 1: if exists a the following pattern: = (..+request.args.get())
        echo $line | grep -E -q "\+request.args.get\(|\+ request.args.get\("
        if [ $? -eq 0 ]; then 
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        #RULE 2: if exists a the following pattern: = (..+request.args[])
        echo $line | grep -q "(.*+request.args\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        #RULE 3: if exists a the following pattern: = (request.POST.get())
        echo $line | grep -q "(request.POST.get(.*%"
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        

        #RULE 4: if exists a the following pattern: = requests.get()
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
                    new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi
            
                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Identification and Authentication Failures"
                                            let id_auth=id_auth+1
                                        fi
                                        if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, SSRF"
                                            let ssrf=ssrf+1
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
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var *\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Identification and Authentication Failures"
                                                let id_auth=id_auth+1
                                            fi
                                            if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, SSRF"
                                                let ssrf=ssrf+1
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
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Identification and Authentication Failures"
                                                    let id_auth=id_auth+1
                                                fi
                                                if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, SSRF"
                                                    let ssrf=ssrf+1
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
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q -i "if $var is None:|if $var is None :|is $var:|is $var :|if not $var:|if not $var :|if $var:|if $var :|if not $var|if $var"
                                            if [ $? -eq 0 ]; then
                                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                                if [ $? -eq 0 ]; then
                                                    if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                        vuln="$vuln, Identification and Authentication Failures"
                                                        let id_auth=id_auth+1
                                                    fi
                                                    if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                        vuln="$vuln, SSRF"
                                                        let ssrf=ssrf+1
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
            
            

        #RULE 5: if exists a the following pattern: return requests.get(...)
        echo $line | grep -q "return requests.get("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $if_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Identification and Authentication Failures"
                        let id_auth=id_auth+1
                    fi
                    if [ $ssrf -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, SSRF"
                        let ssrf=ssrf+1
                    fi
                fi
            fi
        fi
    


        #RULE 6: var is the name of the variable before = input()
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
                new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi
        
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Security Logging and Monitoring Failures"
                            let sec_log=sec_log+1
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                        if [ $? -eq 0 ]; then
                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                            if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Security Logging and Monitoring Failures"
                                let sec_log=sec_log+1
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                                if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Security Logging and Monitoring Failures"
                                    let sec_log=sec_log+1
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"
                                        let inj=inj+1
                                    fi
                                    if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Security Logging and Monitoring Failures"
                                        let sec_log=sec_log+1
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

        #RULE 7: var is the name of the variable before = input()
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
                new_line=$(echo "$new_line" |awk -F" input\\\(" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "escape\($var|escape\($var\)|escape\( $var \)|escape\($var \)|escape\( $var\)|escape_filter_chars\($var\)|escape_filter_chars\($var \)|escape_filter_chars\( $var \)|escape_filter_chars\( $var\)|escape_rdn\($var|escape_rdn\( $var"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Security Logging and Monitoring Failures"
                            let sec_log=sec_log+1
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
                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                            if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Security Logging and Monitoring Failures"
                                let sec_log=sec_log+1
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
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                                if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Security Logging and Monitoring Failures"
                                    let sec_log=sec_log+1
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
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"
                                        let inj=inj+1
                                    fi
                                    if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Security Logging and Monitoring Failures"
                                        let sec_log=sec_log+1
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



        #RULE 8: var is the name of the variable before = ldap3.Server()
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
                new_line=$(echo "$new_line" |awk -F"ldap3.Server\\\(" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi

            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\($var||escape_rdn\( $var"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Injection"                        
                            let inj=inj+1
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                        if [ $? -eq 0 ]; then
                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection" 
                                        let inj=inj+1
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



        #RULE 9: var is the name of the variable before = ldap_connection.search_s()
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
                new_line=$(echo "$new_line" |awk -F"ldap_connection.search_s\\\(" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi
        
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Injection"       
                            let inj=inj+1
                        fi
                    fi
                fi
            else
                ### SECOND CHECK
                echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                        if [ $? -eq 0 ]; then 
                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                vuln="$vuln, Injection"       
                                let inj=inj+1
                            fi
                        fi
                    fi
                else
                    ### THIRD CHECK
                    echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"       
                                    let inj=inj+1
                                fi
                            fi
                        fi
                    else
                        ### FOURTH CHECK
                        echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if $var|if not $var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"       
                                        let inj=inj+1
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


        #RULE 10: if exists a the following pattern: = request.args.get[] and == var
        echo $line | grep -q "request.args.get\[.*==[^a-z]*[a-z]*[^a-z]"
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Broken Access Control"
                        let bac=bac+1
                    fi
                fi
            fi
        fi
        


        #RULE 11: if exists a the following pattern: = urlparse()
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
                new_line=$(echo "$new_line" |awk -F "urlparse\\\(" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
            fi
            
            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
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
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"
                                        let inj=inj+1
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
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
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
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Injection"
                                                let inj=inj+1
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


        #RULE 12: if exists a the following pattern: urlparse(...).function
        echo $line | grep -P -q "urlparse\(.*?\)\.[a-zA-Z]*"
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\(urlparse\(|escape\( urlparse\("
                if [ $? -eq 0 ]; then
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                fi
            fi
        fi



        #RULE 13: if exists a the following pattern: return urlparse(...)
        echo $line | grep -q "return urlparse("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                fi
            fi
        fi



        #RULE 14: if exists a the following pattern: = session[]
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
                new_line=$(echo $new_line | awk -F"session\\\[" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }' | cut -d\] -f$split- )
            fi

            ####	FIRST CHECK
            echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                            if [ $? -eq 0 ]; then
                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
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
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Injection"
                                        let inj=inj+1
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
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
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
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Injection"
                                                let inj=inj+1
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

        

        #RULE 15: if exists a the following pattern: = request.args.get()
        source_function="(flask\\\.)?request\\\.(args|GET|POST|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\.get\\\("
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
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
                
                source_function_alt="(flask\.)?request\.(args|GET|POST|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\.get\("
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\(/")s
                new_line=$(echo $new_line | sed "s/$substitution\($var\)/$substitution\(\)/g")
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" -v i="$i" '{print $(i+1)}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)

                fi

                ####	FIRST CHECK -- MOD WITH %, {} and *
                echo $new_line | grep -E -q "\+ *\b$var\b|= *\b$var\b|= *\b$var\b\\\n|\+ *\b$var\b\\\n|% *\b$var\b|{ *\b$var\b *}"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:|if not $var or" #|if not $var" (SE PROBLEMI togliere if not $var or)
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)" #|logging\.error\(.*(\b$var\b).*?\)" #|yaml.safe_load\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:|if not $var or" #|if not $var"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)" #|yaml.safe_load\(.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *|if not $var or" #|if not $var"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *|if not $var or" #|if not $var"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)" #|yaml.safe_load\(.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
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

        #RULE 16: if exists a the following pattern: = request.args.get()
        source_function=" *= *(flask\\\.)?request\\\.json"
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else                
                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.json($var)/request.json()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.json($var/request.json(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.json(\\\\\"$var\\\\\", $var/request.json(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" -v i="$i" '{print $(i+1)}' | cut -f$split- )
                else
                    new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -f$split-)

                fi

                ####	FIRST CHECK -- MOD WITH %, {} and *
                echo $new_line | grep -E -q "\+ *\b$var\b|= *\b$var\b|= *\b$var\b\\\n|\+ *\b$var\b\\\n|% *\b$var\b|{ *\b$var\b *}"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|in (flask\.)?request\.(files|form|args|GET|POST|params) *:"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
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


        #RULE 17: if exists a the following pattern: return request.args.get(...)
        source_function="return (flask\.)?request\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\.get\(" # source function used for grep: escape with \
        source_function="return (flask\\\.)?request\\\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\.get\\\(" # source function used for awk: escape with \\\
        substitution=$(echo $line | grep -o -E "$source_function") # obtain the specific pattern found by grep and put it in substitution variable
        if [ -n "$substitution" ]; then
            uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]') # change to uppercase for the CNG file
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi

        #RULE 18: if exists a the following pattern: return request.args.get(...)
        source_function="return (flask\.)?request\.(args|args\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\["
        source_function_alt="return (flask\\\.)?request\\\.(args|args\\\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\["
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        if [ -n "$substitution" ]; then
            uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]')
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi


        #RULE 19: if exists a the following pattern: = request.files[]
        source_function="(flask\\\.)?request\\\.(args|args\\\.get|files|form|GET|POST|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\["
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            echo $line | grep -E -q "in request\.(form|files|args|GET|POST|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args) *:"
            if [ $? -eq 0 ]; then
                break
            fi
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
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
                #new_line=$(echo $new_line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.files\[$var\]/request.files\[\]/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" |  sed "s/'$var'/ /g" | sed "s/request.files\[$var/request.files\[/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.files\[\\\\\"$var\\\\\", $var/request.files\[/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                                
                source_function_alt="(flask\.)?request\.(args|GET|POST|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\.get\["
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\[/")s
                new_line=$(echo $new_line | sed "s/$substitution\[$var\]/$substitution\[\]/g")
                # echo "new line $new_line"
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\] -f$split- )
                else
                    new_line=$(echo $new_line | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }' | cut -d\] -f$split- )
                fi
                # ####	FIRST CHECK - MOD WITH %
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n|% *\b$var\b"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if .*endswith\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "in request\.(form|files|args|GET|POST) *:"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|os.path.abspath\(.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)" #|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Insecure Design"
                                            let ins_des=ins_des+1
                                        fi
                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
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
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if .*endswith\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "in request\.(form|files|args|GET|POST) *:" # grep -v -q "in request.form:|in request.form :"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|os.path.abspath\(.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)" #|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Insecure Design"
                                                let ins_des=ins_des+1
                                            fi
                                            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Injection"
                                                let inj=inj+1
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
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if .*endswith\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "in request\.(form|files|args|GET|POST) *:" # grep -v -q "in request.form:|in request.form :"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|os.path.abspath\(.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)" #|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Insecure Design"
                                                    let ins_des=ins_des+1
                                                fi
                                                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Injection"
                                                    let inj=inj+1
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
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(|if .*endswith\("
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "in request\.(form|files|args|GET|POST) *:" # grep -v -q "in request.form:|in request.form :"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|os.path.abspath\(.*(\b$var\b).*?\)|yaml.safe_load\(.*(\b$var\b).*?\)" #|try:.*(\b$var\b).*?\)"
                                            if [ $? -eq 0 ]; then
                                                if [ $? -eq 0 ]; then
                                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                                    if [ $? -eq 0 ]; then
                                                        if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                            vuln="$vuln, Insecure Design"
                                                            let ins_des=ins_des+1
                                                        fi
                                                        if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                            vuln="$vuln, Injection"
                                                            let inj=inj+1
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
            fi
            let i=i+1;
            let check=num_occ+1;
        done

        #RULE 20: if exists a the following pattern: return request.get_data(...)
        source_function="return (flask\.)?request\.(get|urlopen|read|get_data|get_json|from_values)\("
        source_function="return (flask\\\.)?request\\\.(get|urlopen|read|get_data|get_json|from_values)\\\("
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        if [ -n "$substitution" ]; then
            uppercase_substitution=$(echo $substitution | tr '[:lower:]' '[:upper:]')
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi

        #RULE 21: if exists a the following pattern: = request.get_data() or request.read() or request.urlopen()
        source_function=" *= *(flask\\\.)?request\\\.(get|urlopen|read|get_data|get_json|from_values)\\\("
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                source_function_alt="(flask\.)?request\.(get|urlopen|read|get_data|get_json|from_values)\("
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\(/")s
                new_line=$(echo $new_line | sed "s/$substitution\($var\)/$substitution\(\)/g")
                
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\(" #|logging\.error\(.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                else
                    ### SECOND CHECK
                    echo $new_line | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(" #|logging\.error\(.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    else
                        ### THIRD CHECK
                        echo $new_line | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(" #|logging\.error\(.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
                                            fi
                                        fi
                                    fi
                                fi 
                            fi
                        else
                            ### FOURTH CHECK
                            echo $new_line | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(" #|logging\.error\(.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)|yaml\.safe_load\(.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
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


        #RULE 22: if exists a the following pattern: = os.environ.get() or = json.loads()
        source_function=" *= *os\\\.environ\\\.get\\\("
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                #check if there are var not strings
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi
                source_function_alt=" *= *os\.environ\.get\("
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\(/")s
                new_line=$(echo $new_line | sed "s/$substitution\($var\)/$substitution\(\)/g")

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
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
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
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
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
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
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
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

        #RULE 23: if exists a the following pattern: = os.environ.get() or = json.loads()
        source_function="json\\\.loads\\\("
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
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
                new_line=$(echo $line | sed "s/$var(/func(/g"  | sed "s/SELECT $var:/ /g" | sed "s/SELECT $var :/ /g" | sed "s/def $var(/def func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g" | sed "s/request.args.get($var)/request.args.get()/g" | sed "s/'$var '/ /g" | sed "s/\"$var/ /g" | sed "s/\" $var/ /g" | sed "s/$var\"/ /g" |  sed "s/$var\", $var\"/ /g" | sed "s/$var\", $var/ /g" | sed "s/$var \"/ /g"| sed "s/'$var'/ /g" | sed "s/request.args.get($var/request.args.get(/g" | sed "s/\\\\\"$var\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var\\\\\", $var/request.args.get(/g" | sed "s/$var =()/ /g" | sed "s/$var()/ /g" )
                let split=i;
                let split=split+1;
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi
                source_function_alt="json\.loads\("
                substitution=$(echo $line | grep -o -E "$source_function_alt")
                substitution=$(echo $line | sed "s/\(/")s
                new_line=$(echo $new_line | sed "s/$substitution\($var\)/$substitution\(\)/g")

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
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
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
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
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
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
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
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



        #RULE 24: if exists a the following pattern: def SOMETHING(var1,var2,...,varn): 
        source_function="def [[:alnum:]_]+\\\(" # def SOMETHING(var):
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        num_commas=0;
        num_vars=0;
        while [ $i -le $num_occ ]; do
            let split=i; # if it does not work put -f1 instead of -f$split
            var=$(echo "$line" | awk -F "$source_function" -v i="$i" '{print $(i+1)}'| cut -d\) -f1)
            if [ -z "$var" ]; then
                pass=1;
            else                 
                if [[ "$var" == *","* ]]; then # if there are commas, update the num_commas variable
                    num_commas=$(echo "$var" | tr -cd ',' | wc -c)
                fi
                let num_vars=num_commas+1 # ex: var1,var2 -> one comma and two variables
                j=1
                while [ $j -le $num_vars ]; do
                    let split_part=j
                    let split_part=split_part+1
                    var_part=$(echo "$var" | awk -v j="$j" -F, '{print $j}' | cut -d',' -f$split_part-) # take j-th variable
                    #check if there are var not strings
                    new_line=$(echo $line | sed "s/$var_part(/func(/g"  | sed "s/SELECT $var_part:/ /g" | sed "s/SELECT $var_part :/ /g" | sed "s/def $var_part(/def func(/g" | sed "s/$var_part =/ =/g" | sed "s/$var_part=/ =/g" | sed "s/request.args.get($var_part)/request.args.get()/g" | sed "s/'$var_part '/ /g" | sed "s/\"$var_part/ /g" | sed "s/\" $var_part/ /g" | sed "s/$var_part\"/ /g" |  sed "s/$var_part\", $var_part\"/ /g" | sed "s/$var_part\", $var_part/ /g" | sed "s/$var_part \"/ /g"| sed "s/'$var_part'/ /g" | sed "s/request.args.get($var_part/request.args.get(/g" | sed "s/\\\\\"$var_part\\\\\"/ /g" | sed "s/request.args.get(\\\\\"$var_part\\\\\", $var_part/request.args.get(/g" | sed "s/$var_part =()/ /g" | sed "s/$var_part()/ /g" )
                    let split=i;
                    #let split=split+1;
                    if [ $num_occ -eq 1 ]; then
                        new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f2- )
                    else
                        new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                    fi
                    rule1="'<.*href.*'.*\b$var_part\b" # HTML RULE
                    rule2="os\.system\(.*(\b$var_part\b).*?\)|sh\.grep\(.*(\b$var_part\b).*?\)|subprocess\.(run|call|capture_output)\(.*(\b$var_part\b).*?\)|_xxsubinterpreters\.run_string\(.*(\b$var_part\b).*?\)|DYNAMO_CLIENT\.scan\(.*(\b$var_part\b).*?\)|console\.push\(.*(\b$var_part\b).*?\)|re\.sub\(.*(\b$var_part\b).*?\)" # os functions rule
                    rule3="cursor\.execute\(.*(\b$var_part\b).*?\)"
                    echo $new_line | grep -P -q "($rule1|$rule2|$rule3)"
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\("
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var_part\b).*?\], check=True|subprocess.run\(.*(\b$var_part\b).*?\], check =True|subprocess.run\(.*(\b$var_part\b).*?\], check= True|subprocess.run\(.*(\b$var_part\b).*?\], check = True|subprocess.run\(.*(\b$var_part\b).*?\],check=True|subprocess.run\(.*(\b$var_part\b).*?\],check =True|subprocess.run\(.*(\b$var_part\b).*?\],check= True|subprocess.run\(.*(\b$var_part\b).*?\],check = True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var_part\b).*?\)|try:.*(\b$var_part\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "escape\( *$var_part *\)|escape_filter_chars\( *$var_part *\)|escape_rdn\( *$var_part"
                                    if [ $? -eq 0 ]; then
                                        if [ $inj -eq 0 ]; then # Toggle the category var_partiable for the specific snippet
                                            vuln="$vuln, Injection"
                                            let inj=inj+1
                                        fi
                                    fi
                                fi
                            fi 
                        fi
                    fi
                    let j=j+1
                done
            fi
            let i=i+1;
            let check=num_occ+1;
        done


        #RULE 25: if exists a the following pattern: (... + request.args.get(...))
        source_function="\+ *(flask\.)?request\.(args|args\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\["
        source_function_alt="\\\+ *(flask\\\.)?request\\\.(args|args\\\.get|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\["
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        #if [ $? -eq 0 ]; then
        if [ -n "$substitution" ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\(|os\.path\.isfile\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi

        #RULE 26: if exists a the following pattern: (... + request.args.get(...))
        source_function="\+ *(flask\.)?request\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\.get\("
        source_function_alt="\\\+ *(flask\.)?request\\\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\.get\\\("
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        #if [ $? -eq 0 ]; then
        if [ -n "$substitution" ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\(|os\.path\.isfile\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi


        #RULE 27: if exists a the following pattern: = '{}'.format(request.form)
        source_function="'\\\{\\\}'.format\\\((flask\\\.)?request\\\.(args|POST|GET|files|form|data|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\["
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
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
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\] -f$split- )
                else
                    new_line=$(echo $new_line | awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }' | cut -d\] -f$split- )
                fi

                ####	FIRST CHECK
                echo $new_line | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b|=\b$var\b\\\n|= \b$var\b\\\n|\+\b$var\b\\\n|\+ \b$var\b\\\n"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
                    if [ $? -eq 0 ]; then
                        echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                        if [ $? -eq 0 ]; then
                            echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                if [ $? -eq 0 ]; then
                                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
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
                            echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                            if [ $? -eq 0 ]; then
                                echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                    if [ $? -eq 0 ]; then
                                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                            vuln="$vuln, Broken Access Control"
                                            let bac=bac+1
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
                                echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                if [ $? -eq 0 ]; then
                                    echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                        if [ $? -eq 0 ]; then
                                            if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                vuln="$vuln, Broken Access Control"
                                                let bac=bac+1
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
                                    echo $new_line | grep -v -P -i -q "subprocess.run\(.*(\b$var\b).*?\], *check *= *True"
                                    if [ $? -eq 0 ]; then
                                        echo $new_line | grep -P -v -q "os.path.isfile\(.*(\b$var\b).*?\)|try:.*(\b$var\b).*?\)"
                                        if [ $? -eq 0 ]; then
                                            echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                                            if [ $? -eq 0 ]; then
                                                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                                                    vuln="$vuln, Broken Access Control"
                                                    let bac=bac+1
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
        
        #RULE 28: if exists a the following pattern: ( request.args.get(...))
        source_function="\( *(flask\.)request\.(args|args\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\("
        source_function_alt="\\\( *(flask\\\.)request\\\.(args|args\\\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\("
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        #if [ $? -eq 0 ]; then
        if [ -n "$substitution" ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi


        #RULE 29: if exists a the following pattern: (... + request.args.get(...))
        source_function="\% *(flask\.)request\.(args|args\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\("
        source_function_alt="\\\% *(flask\\\.)request\\\.(args|args\\\.get|POST|GET|files|formdata|headers|params|base_url|authorization|cookies|endpoint|host|host_url|module|path|query_strings|url|values|view_args)\\\("
        substitution=$(echo $line | grep -o -E "$source_function") # -o restituisce SOLO la parte corrispondente al modello cercato
        #if [ $? -eq 0 ]; then
        if [ -n "$substitution" ]; then
            echo $line | grep -E -v -q "if.*\.match\(|if obj_match\("
            if [ $? -eq 0 ]; then
                echo $new_line | grep -E -v -q "escape\( *$var|escape\( *$var *\)|escape_filter_chars\( *$var *\)|escape_rdn\( *$var"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1;
                    fi
                fi
            fi
        fi
        
        # RULE 13F
        source_function="(locals\\\(|globals\\\()"
        num_occ=$(echo $line | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        while [ $i -le $num_occ ]; do
            var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' |  awk '{print $NF}')
            if [ -z "$var" ]; then
                pass=1;
            else
                if [ $var == "=" ]; then
                    var=$(echo $line | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
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
                    new_line=$(echo $new_line | awk -F "$source_function" '{print $2}' | cut -d\) -f$split- )
                else
                    new_line=$(echo "$new_line" |awk -F"$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }'| cut -d\) -f$split-)
                fi
                regex="(django\.shortcuts\.)?render\(.*\b$var\b.*\)"
                if  echo "$new_line" | grep -q -E "$regex"; then       
                    if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1;
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        rule1="(django\.shortcuts\.)?render\(.*locals\(\).*\)"
        rule2="(django\.shortcuts\.)?render\(.*globals\(\).*\)"
        regex="($rule1|$rule2)"
        if  echo "$new_line" | grep -q -E "$regex"; then 
            if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                vuln="$vuln, Injection"
                let inj=inj+1;
            fi
        fi

        #RULE 30: detection of Markup()/Markup.unescape() --> use Markup.escape() instead
        echo $line | grep -E -q "Markup\(|Markup\.unescape\("
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        #RULE 31: detection of function(... var = input() ...)
        regex="\(.*= *input\(\).*\)"
        echo "$line" | grep -E -q -i "$regex"
        if  [ $? -eq 0 ]; then   
            if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                vuln="$vuln, Injection"
                let inj=inj+1;
            fi
        fi

        #RULE 32: detection of function(... var = input() ...)
        regex="(import csv|csv\.writer)"
        echo "$line" | grep -E -q -i "$regex"
        if  [ $? -eq 0 ]; then  
            if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                vuln="$vuln, Injection"
                let inj=inj+1;
            fi
        fi

        #RULE 33: detection of subprocess.SOMETHING(...) ---> subprocess.run(...,check=True)
        regex="subprocess\.capture_output\(" #|subprocess.call\("
        echo "$line" | grep -E -q -i "$regex"
        if  [ $? -eq 0 ]; then 
            if [ $inj -eq 0 ]; then #I count the single category occurence per snippet
                vuln="$vuln, Injection"
                let inj=inj+1;
            fi
        fi



        ########        START KNOWN UNSAFE FUNCTIONS            ########
        #RULE 34: detection of yaml.load() function
        echo $line | grep -E -q -i "yaml\.load\("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "yaml\.load\([^,]+,[ ]*Loader=yaml\.SafeLoader\)"
            if [ $? -eq 0 ]; then
                echo $line | grep -E -v -q "yaml\.load\([^,]+,[ ]*Loader=yaml\.FullLoader\)"
                if [ $? -eq 0 ]; then
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                    if [ $soft_data -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection, Software and Data Integrity Failures"
                        let soft_data=soft_data+1
                    fi
                fi
            fi
        fi



        #RULE 35: detection of eval() function
        echo $line | grep -E -q -i "\(eval\(| eval\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "def eval("
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi


        # MOD - CLUSTER 2 + CLUSTER 8
        #RULE 36: detection of exec() function 
        echo $line | grep -E -q -i "exec\(|execv\(|execl\(" 
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi


        #RULE 37: detection of subprocess() function 
        echo $line | grep -E -q -i "subprocess\..*\(.*shell\s*=\s*True"
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi



        #RULE 38: detection of traceback.format_exc() function without saving output in a variable
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
                if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Insecure Design"
                    let ins_des=ins_des+1
                fi
            fi
        fi



        #RULE 39: detection of run(debug=True) function
        echo $line | grep -E -q -i "run\(debug=True\)|.run\(debug=True\)|run\( debug=True \)|.run\( debug=True \)|run\( debug=True\)|.run\( debug=True\)|run\(debug=True \)|.run\(debug=True \)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]run("
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi



        #RULE 40: detection of ftplib.FTP() function
        echo $line | grep -E -q -i "ftplib.FTP\(|FTP\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]FTP("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -i -q " FTP()"
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi



        #RULE 41: detection of smtplib.SMTP() function
        echo $line | grep -E -q -i "smtplib.SMTP\(|SMTP\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]SMTP("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -i -q " SMTP()"
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi                  
                fi
            fi
        fi



        #RULE 42: detection of hashlib.sha256() function
        echo $line | grep -E -q -i "hashlib.sha256\(|sha256\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]sha256("
            if [ $? -eq 0 ]; then
            echo $line | grep -v -i -q " sha256("
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi



        #RULE 43: detection of DSA.generate() function with value less (or equal) than 1024
        echo $line |  grep -E -i -q "DSA.generate\((0|1|2|4|8|16|32|64|128|256|512|1024|)\)"
        if [ $? -eq 0 ]; then
            value=$(echo $line | awk -F 'DSA.generate\\(' '{print $2}' | awk -F  ')' '{print $1}')
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi



        #RULE 44: detection of DES.new() function
        echo $line | grep -q -i " DES.new("
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi



        #RULE 45: detection of ssl.wrap_socket() function
        echo $line | grep -q -i "ssl.wrap_socket("
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi



        #RULE 46: detection of hashlib.md5() function
        echo $line | grep -E -q -i "hashlib.md5\(|md5\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]md5("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi



        #RULE 47: detection of hashlib.sha1() function
        echo $line | grep -E -q -i "hashlib.sha1\(|sha1\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]sha1("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi



        #RULE 48: detection of algorithms.AES() function
        new_line=$(echo $line | sed "s/AES(__name__)/ /g" | sed "s/def AES(/def func(/g" | sed "s/return AES():/ /g" | sed "s/AES =/ /g" | sed "s/AES=/ /g" )
        echo $new_line | grep -E -q -i "algorithms.AES\(|AES\("
        if [ $? -eq 0 ]; then
            echo $new_line | grep -v -q "[a-zA-Z0-9]AES("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi



        #RULE 49: detection of modes.CBC() function
        echo $line | grep -E -q -i "modes.CBC\(|AES.MODE_CBC"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]CBC("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def CBC("
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi




        #RULE 50: detection of random.randint() function
        echo $line | grep -E -q -i "random.randint\(|randint\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]randint("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi      
            fi
        fi



        #RULE 51: detection of random.choice() function
        echo $line | grep -E -q -i "random.choice\(|choice\(|random.choices\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]choice("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "secrets.choice("
                if [ $? -eq 0 ]; then
                    echo $line | grep -v -q "secrets\."
                    if [ $? -eq 0 ]; then
                        if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Cryptographic Failures"
                            let crypto=crypto+1
                        fi
                    fi
                fi

            fi
        fi



        #RULE 52: detection of random.getrandbits() function
        echo $line | grep -E -q -i "random.getrandbits\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]getrandbits("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "secrets\."
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi



        #RULE 53: detection of jwt.process_jwt() function
        echo $line | grep -E -q -i "jwt.process_jwt\([a-zA-Z0-9]*[^,]\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]process_jwt("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "verify_jwt("
                if [ $? -eq 0 ]; then
                    token=$(echo $line | awk -F 'jwt.process_jwt\\(' '{print $2}' | awk -F  ')' '{print $1}')
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi



        #RULE 54: detection of mktmp() function
        echo $line | grep -E -q -i "mktemp\(|\.mktemp\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]mktemp("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def mktemp("
                if [ $? -eq 0 ]; then
                    if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Broken Access Control"
                        let bac=bac+1
                    fi
                fi
            fi
        fi



        #RULE 55: detection of time.clock() function
        echo $line | grep -E -q -i "time.clock\(|clock\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]clock("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "def clock("
                if [ $? -eq 0 ]; then
                    if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                fi
            fi
        fi



        #RULE 56: detection of pickle functions
        new_line=$(echo $line | sed "s/import cPickle/ /g" | sed "s/import pickle/ /g" | sed "s/import [a-zA-Z0-9]cPickle/ /g" | sed "s/import _pickle/ /g" | sed "s/pickle.this/ /g" )
        echo $new_line | grep -E -q -i "pickle\.loads\(|pickle\.load\(|pickle\.dump\(|pickle\.dumps\(|pickle\.Unpickler\(|cPickle\.loads\(|cPickle\.load\(|cPickle\.dump\(|cPickle\.dumps\(|cPickle\.Unpickler\("
        if [ $? -eq 0 ]; then
            echo $new_line | grep -v -q "\b[a-zA-Z0-9]pickle\b"
            if [ $? -eq 0 ]; then
                echo $new_line | grep -v -q "\b[a-zA-Z0-9]cPickle\b"
                if [ $? -eq 0 ]; then
                    if [ $soft_data -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Software and Data Integrity Failures"
                        let soft_data=soft_data+1
                    fi
                fi
            fi
        fi



        #RULE 57: detection of xml.sax.make_parser() function
        echo $line | grep -E -q -i "xml.sax.make_parser\(|xml\.sax\."
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]xml\.sax\."
            if [ $? -eq 0 ]; then
                echo $line | grep -E -v -q -i "setFeature\(feature_external_ges, False\)|setFeature\(feature_external_ges,False\)"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1
                    fi
                fi
            fi
        fi

        #RULE 58: detection of assert
        echo $line | grep -E -q -i "\bassert\b| \bassert\b"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]assert"
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "except AssertionError"
                if [ $? -eq 0 ]; then 
                    if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1
                    fi
                fi
            fi
        fi



        #RULE 59: detection of hashlib.new() function with a single param
        echo $line | grep -q -i "hashlib.new([^a-z]*[a-zA-Z0-9]*[^,][^a-Z]*)"
        if [ $? -eq 0 ]; then
            protocol=$(echo $line | awk -F 'hashlib.new\\(' '{print $2}' | awk -F '\\)' '{print $1}')
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi



        #RULE 60: detection of pbkdf2_hmac() function
        echo $line | grep -E -q -i "pbkdf2_hmac\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]pbkdf2_hmac("
            if [ $? -eq 0 ]; then
                protocol=$(echo $line | awk -F 'pbkdf2_hmac\\(' '{print $2}' | awk -F ',' '{print $1}')
                echo $protocol | grep -E -q -i "sha512|sha3_224|sha3_256|sha3_384|sha3_512" #whitelisting
                if [ $? -eq 1 ]; then #are used protocols different form the selected ones
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi



        #RULE 61: detection of parseUDPpacket() function
        echo $line | grep -E -q -i "parseUDPpacket\("
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]parseUDPpacket("
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi



        #RULE 62: detection of os.system(...file.bin...) function
        echo $line | grep -E -q -i "os.system\([^a-z]*[a-z]*\.bin"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]os.system([^a-z]*[a-z]*\.bin"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi



        #RULE 63: detection of exec() and os.system() function
        echo $line | grep -E -q -i "\(exec, \('import os;os.system\(|\(exec,\('import os;os.system\(|\(exec,\('import os ; os.system\(|\(exec, \('import os ; os.system\("
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi



        #RULE 64: detection of etree.ElementTree library
        echo $line | grep -q -i "etree.ElementTree as ET.*ET\."
        if [ $? -eq 0 ]; then
            if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi



        #RULE 65: detection of GENERIC 'raisePrivilege() function() lowPrivilege()'
        echo $line | grep -q -i "raisePrivileges().*lowerPrivileges()"
        if [ $? -eq 0 ]; then
            if [ $ins_des -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Insecure Design"
                let ins_des=ins_des+1
            fi
        fi



        #RULE 66: detection of GENERIC 'requests.get(..., verify=False)'
        echo $line | grep -q "requests\..*(.*verify=False"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]requests\."
            if [ $? -eq 0 ]; then
                if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Identification and Authentication Failures"
                    let id_auth=id_auth+1
                fi
            fi
        fi






        ########            START CONFIGURATION PROBLEM        ########
        #RULE 67: detection of os.chmod() function
        #echo $line | grep -E -q -i "os.chmod\(.*, 0000\)|os.chmod\(.*, 0o400\)|os.chmod\(.*, 128\)|os.chmod\(.*, 755)|os.chmod\(.*, 0o755\)|os.chmod\(.*, 777)|os.chmod\(.*, 0o777\)"
        echo $line | grep -E -q -i "os.chmod\(.*, 0000\)|os.chmod\(.*, 755)|os.chmod\(.*, 0o755\)|os.chmod\(.*, 777)|os.chmod\(.*, 0o777\)"
        if [ $? -eq 0 ]; then
            if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi



        #RULE 68: detection of response.set_cookie() with plaintext password
        new_line=$(echo $line | sed "s/def set_cookie()/ /g" | sed "s/set_cookie(__name__)/ /g" )
        echo $new_line | grep -E -q -i "\.set_cookie\(.*, [a-zA-Z0-9]*\)|set_cookie\(.*, [a-zA-Z0-9]*\)|\.set_cookie\([^a-z]*[a-zA-Z0-9]*[^a-z]*\)|set_cookie\([^a-z]*[a-zA-Z0-9]*[^a-z]*\)"
        if [ $? -eq 0 ]; then
            echo $new_line | grep -v -q -i "\.set_cookie()"
            if [ $? -eq 0 ]; then
                token=$(echo $line | awk -F 'set_cookie\\(' '{print $2}' | awk -F  ')' '{print $1}' )
                split_token=$(echo $line | awk -F  ',' '{print $2}' | awk -F  ')' '{print $1}')
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi



        #RULE 69: detection of 'ctx.check_hostname = False' AND 'ctx.verify_mode = ssl.CERT_NONE'
        echo $line | grep -q -i "ssl.create_default_context() .* ctx.verify_mode = ssl.CERT_NONE"
        if [ $? -eq 0 ]; then
            hostname=$(echo $line | awk -F 'check_hostname' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            cert=$(echo $line | awk -F 'verify_mode' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi



        #RULE 70: detection of 'ssl._create_unverified_context()'
        echo $line | grep -E -q -i "ssl._create_unverified_context()|ctx._create_unverified_context = True"
        if [ $? -eq 0 ]; then
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi



        #RULE 71: detection of 'ssl._create_stdlib_context()'
        echo $line | grep -q -i "ssl._create_stdlib_context()"
        if [ $? -eq 0 ]; then
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi



        #RULE 72: detection of 'ssl.create_default_context()' AND'ctx.check_hostname = False'
        echo $line | grep -q -i "check_hostname = false"
        if [ $? -eq 0 ]; then
            hostname=$(echo $line | awk -F 'check_hostname' '{print $2}' | awk -F '=' '{print $2}' | awk -F ' ' '{print $1}')
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi



        #RULE 73: detection of SSL.TLSv1_2_METHOD
        echo $line | grep -q -i "SSL.TLSv1_2_METHOD"
        if [ $? -eq 0 ]; then
            if [ $id_auth -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi



        #RULE 74: detection of urandom() with value less than 64
        echo $line |  grep -E -i -q "urandom\((0|1|2|4|8|16|32)\)|urandom\( (0|1|2|4|8|16|32) \)|urandom\( (0|1|2|4|8|16|32)\)|urandom\((0|1|2|4|8|16|32) \)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q -i "[a-zA-Z0-9]urandom"
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi



        #RULE 75: detection of 'key_size' less than 2048
        echo $line | grep -E -q -i "key_size=([1-9] |[1-1][0-9][0-9] |[1-1][0-9][0-9][0-9] |204[0-7] )|key_size=([1-9]\\\n |[1-1][0-9][0-9]\\\n |[1-1][0-9][0-9][0-9]\\\n |204[0-7]\\\n )"
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi



        #RULE 76: detection of 'jwt.decode(..., verify = False)'
        echo $line | grep -E -q -i "jwt.decode\(.*verify = False|jwt.decode\(.*verify=False"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]decode("
            if [ $? -eq 0 ]; then
                echo $line | grep -v -q "([a-zA-Z0-9]verify = False"
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi



        #RULE 77: detection of 'jwt.decode(token)'
        echo $line | grep -E -q -i "jwt.decode\([a-zA-Z0-9]*\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]decode("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi



        #RULE 78: detection of 'jwt.decode(token, key, options={\"verify_signature\": False}..)'
        echo $line | grep -q -i "jwt.decode(.*, options={[^a-z]*verify_signature[^a-z]* False"
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi




        #RULE 79: detection of 's.bind(('0.0.0.0', ...))'
        echo $line | grep -P -q -i "\.bind\(\(.*0.0.0.0.*?\)\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]bind\(\('0.0.0.0',.*\)\)"
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi



        #RULE 80: detection of 'etree.XMLParser(resolve_entities=True)' AND 'XMLParser(resolve_entities=True)' OR 'etree.XMLParser()' AND 'XMLParser()'
        echo $line | grep -E -q -i "etree.XMLParser\(resolve_entities=True\)|XMLParser\(resolve_entities=True\)|XMLParser\(\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]XMLParser("
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi



        #RULE 81: detection of 'etree.XSLTAccessControl(read_network=True...)' AND 'XSLTAccessControl(read_network=True...)'
        echo $line | grep -E -q -i "etree.XSLTAccessControl\(.*read_network=True|XSLTAccessControl\(.*read_network=True|XSLTAccessControl\(.*write_network=True"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]XSLTAccessControl(.*read_network=True"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi



        #RULE 82: detection of 'os.chmod(file.bin)'
        echo $line | grep -E -q -i "os.chmod\([^a-z]*[a-z]*\.bin"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q "[a-zA-Z0-9]os.chmod([^a-z]*[a-z]*\.bin"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi


        #RULE 83: detection of INCREMENT
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
                    if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Logging and Monitoring Failures"
                        let sec_log=sec_log+1
                    fi
                fi
            fi  
        fi



        #RULE 84: detection of lock
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
                    if [ $sec_log -eq 0 ]; then # Toggle the category variable for the specific snippet
                        vuln="$vuln, Security Logging and Monitoring Failures"
                        let sec_log=sec_log+1
                    fi
                fi
            fi
        fi



        #RULE 85: detection of with open ... as value: ... value.read()
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
                        if [ $bac -eq 0 ]; then # Toggle the category variable for the specific snippet
                            vuln="$vuln, Broken Access Control"
                            let bac=bac+1
                        fi
                    fi
                fi

            fi
            let i=i+1;
            let check=num_occ+1;
        done

##################################################sql 8F CLUSTER 6
        rule8="(\"SELECT|\"DELETE|\"UPDATE|\"INSERT).*\" *% *\(?(flask\.)?request.*\.get\(.*\)\)?"
        rule9="(\"SELECT|\"DELETE|\"UPDATE|\"INSERT).*\" *.format\((flask\.)?request.*\.get\(.*\)\)"
        rule10="('SELECT|'DELETE|'UPDATE|'INSERT).*{(flask\.)?request.*\.get\(.*\)}'" # snippet linea 7, non funziona
        # negli snippet originali la source è una variabile request passata in input dall'utente
        # qui semplicemente verifico se c'è una chiamata a una funzione SQL senza i prepared statements
        #ma non verifico che la variabile sia user controlled --> potrebbe sicuramente causare falsi positivi
        rule11="(order_by|filter|like|group_by|join|like|distinct|extra)\(.*\.format\(.*\)\).*" # esempio: query = query.order_by("string{}".format(var))
        rule12="(order_by|filter|like|group_by|join|like|distinct|extra)\(.*%.*\).*" # esempio: query = query.order_by("string{}".format(var))
        regex="($rule8|$rule9|$rule10|$rule11|$rule12)"
        if echo "$new_line" | grep -q -E "$regex"; then
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        ######################## RULE 18F - CLUSTER 12 ENVIRONMENT pattern: Environment() or Environment(autoescape=False)
        echo "$line" | grep -q "Environment("
        # Controlla il risultato di grep
        if [ $? -eq 0 ]; then
            # Se la riga contiene "Environment()", verifica che non contenga "autoescape=True" o "autoescape=select_autoescape"
            echo "$line" | grep -E -q -v "autoescape *= *True|autoescape *= *select_autoescape"            
            # Controlla il risultato di grep -v
            if [ $? -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi



        #final timestamp all rules for snippet
        end_snippet=$(date +%s.%N)   
        if [ $name_os = "Darwin" ]; then  #MAC-OS system
            runtime_snippet=$( echo "$end_snippet - $start_snippet" | bc -l )
        elif [ $name_os = "Linux" ]; then #LINUX system 
            runtime_snippet=$(python3 -c "print(${end_snippet} - ${start_snippet})")
        fi


        ##################          ADJUSTING DATA         #######################
        line=$(echo $line | sed "s/PRODUCT_SYMBOL/*/g")
        


        ##################          FINAL CHECK         #######################
        if [[ ! $vuln ]]; then
            { echo "==> SAFE CODE"; echo "["; echo "$runtime_snippet"; echo "s ]"; echo ":"; echo "$line"; } | tr "\n" " " >> $2;
            echo -e "\n" >> $2;
            let dimtestset=dimtestset+1;
        else
            { echo "(!) VULN CODE"; echo "["; echo "$runtime_snippet"; echo "s ]"; echo $vuln; echo ":"; echo "$line"; } | tr "\n" " " >> $2;
            echo -e "\n" >> $2;
            let countvuln=countvuln+1;
            let dimtestset=dimtestset+1;
        fi



        ##################          FINAL COUNT VULNERABILITIES         #######################
        # For each line, if a category was toggled, increment the global counter for that category
        if [ $inj -gt 0 ]; then
            ((inj_count++))
        fi
        if [ $crypto -gt 0 ]; then
            ((crypto_count++))
        fi
        if [ $sec_mis -gt 0 ]; then
            ((sec_mis_count++))
        fi
        if [ $bac -gt 0 ]; then
            ((bac_count++))
        fi
        if [ $id_auth -gt 0 ]; then
            ((id_auth_count++))
        fi
        if [ $sec_log -gt 0 ]; then
            ((sec_log_count++))
        fi
        if [ $ins_des -gt 0 ]; then
            ((ins_des_count++))
        fi
        if [ $ssrf -gt 0 ]; then
            ((ssrf_count++))
        fi
        if [ $soft_data -gt 0 ]; then
            ((soft_data_count++))
        fi

    fi

done < "$input"

##################          RULES COMPUTATIONAL TIME         ########################### 
end=$(date +%s.%N)   
if [ $name_os = "Darwin" ]; then  #MAC-OS system
    runtime=$( echo "$end - $start" | bc -l )
elif [ $name_os = "Linux" ]; then #LINUX system 
    runtime=$(python3 -c "print(${end} - ${start})")
fi



##################          RESULTS ON FILE         ########################### 
#DET file
echo -e "\n\n\n" >> $2;
echo -e "=================>          DATASET SIZE         <=================\n" >> $2;
{ echo "#DimTestSet:"; echo $dimtestset; } | tr "\n" " " >> $2;
echo -e "\n\n\n" >> $2;

echo -e "=================>    FINAL RESULTS DETECTION    <=================\n" >> $2;
{ echo "#TotalVulnerabilities:"; echo $countvuln; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "#SafeCode:";  awk -v var1=$dimtestset -v var2=$countvuln 'BEGIN { if(var1!=0) { print  ( var1 - var2 )  } else {print 0} }'; } | tr "\n" " "  >> $2;
echo -e "\n" >> $2;
{ echo "Vulnerability Rate:"; awk -v var1=$countvuln -v var2=$dimtestset 'BEGIN { if(var2!=0) { print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " "  >> $2;
echo -e "\n\n\n" >> $2;

echo -e "=================>        OWASP CATEGORIES       <=================\n" >> $2;
{ echo "#Injection:"; echo $inj_count; } | tr "\n" " " >> $2
echo -e "\n" >> $2;
{ echo "#Cryptographic Failures:"; echo $crypto_count; } | tr "\n" " " >> $2
echo -e "\n" >> $2;
{ echo "#Security Misconfiguration:"; echo $sec_mis_count; } | tr "\n" " " >> $2
echo -e "\n" >> $2;
{ echo "#Broken Access Control:"; echo $bac_count; } | tr "\n" " " >> $2
echo -e "\n" >> $2;
{ echo "#Identification and Authentication Failures:"; echo $id_auth_count; } | tr "\n" " " >> $2
echo -e "\n" >> $2;
{ echo "#Security Logging and Monitoring Failures:"; echo $sec_log_count; } | tr "\n" " " >> $2
echo -e "\n" >> $2;
{ echo "#Insecure Design:"; echo $ins_des_count; } | tr "\n" " " >> $2
echo -e "\n" >> $2;
{ echo "#SSRF:"; echo $ssrf_count; } | tr "\n" " " >> $2
echo -e "\n" >> $2;
{ echo "#Software and Data Integrity Failures:"; echo $soft_data_count; } | tr "\n" " " >> $2
echo -e "\n\n\n" >> $2;


#####
echo -e "=================>        EXECUTION TIME        <=================\n" >> $2;
{ echo "Runtime:"; echo $runtime; echo "s"; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;
{ echo "Average runtime per snippet:"; awk -v var1=$runtime -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) } else {print 0} }'; echo "s"; } | tr "\n" " " >> $2;
echo -e "\n" >> $2;


##################          RESULTS ON PROMPT         ########################### 
echo -e "\n";
echo -e "=================>          DATASET SIZE         <=================\n";
{ echo "#DimTestSet:"; echo $dimtestset; } | tr "\n" " ";
echo -e "\n\n\n";

echo -e "=================>    FINAL RESULTS DETECTION    <=================\n";
{ echo "#TotalVulnerabilities:"; echo $countvuln; } | tr "\n" " ";
echo -e "\n";
{ echo "#SafeCode:";  awk -v var1=$dimtestset -v var2=$countvuln 'BEGIN { if(var1!=0) { print  ( var1 - var2 )  } else {print 0} }'; } | tr "\n" " ";
echo -e "\n";
{ echo "Vulnerability Rate:"; awk -v var1=$countvuln -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " ";
echo -e "\n\n\n";

echo -e "=================>        OWASP CATEGORIES       <=================\n";
{ echo "#Injection:"; echo $inj_count; } | tr "\n" " ";
echo -e "\n";
{ echo "#Cryptographic Failures:"; echo $crypto_count; } | tr "\n" " ";
echo -e "\n";
{ echo "#Security Misconfiguration:"; echo $sec_mis_count; } | tr "\n" " ";
echo -e "\n";
{ echo "#Broken Access Control:"; echo $bac_count; } | tr "\n" " ";
echo -e "\n";
{ echo "#Identification and Authentication Failures:"; echo $id_auth_count; } | tr "\n" " ";
echo -e "\n";
{ echo "#Security Logging and Monitoring Failures:"; echo $sec_log_count; } | tr "\n" " ";
echo -e "\n";
{ echo "#Insecure Design:"; echo $ins_des_count; } | tr "\n" " ";
echo -e "\n";
{ echo "#SSRF:"; echo $ssrf_count; } | tr "\n" " ";
echo -e "\n";
{ echo "#Software and Data Integrity Failures:"; echo $soft_data_count; } | tr "\n" " ";
echo -e "\n\n\n";


echo -e "=================>        EXECUTION TIME        <=================\n";
{ echo "Runtime:"; echo $runtime; echo "s"; } | tr "\n" " ";
echo -e "\n";
{ echo "Average runtime per snippet:"; awk -v var1=$runtime -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) } else {print 0} }'; echo "s"; } | tr "\n" " ";
echo -e "\n\n";