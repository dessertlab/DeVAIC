# Function to add a rule to TRIGGERED_RULES array and a variable to INJECTED_VARS array
trigger_rule () {
    # New remediation index
    local new_rem=$1
    TRIGGERED_RULES+=($new_rem)    

    # New injected var. It is already set to NO_VAR if there's no var to inject.
    local new_injected_var=$2
    INJECTED_VARS+=($new_injected_var)
}

standard_rule () {

    local line="$1"
    local pattern="$2"
    local pattern_not_list="$3"
    local index="$4"
    local rule_id="$5"
    local vulnerabilities="$6"
    local injected_var="$7"
    local fragments=()

    # Replace the 'VAR_PLACEHOLDER' literal with $var actual value in pattern
    pattern="${pattern//VAR_PLACEHOLDER/$var}"  

    #echo "rule_id: $rule_id"
    #echo "pattern: $pattern"

    if echo "$line" | grep -qP "$pattern"; then
        #if [ $? -eq 0 ]; then
        #    echo -e "\nRule triggered: $rule_id"
        #fi
        
        #echo "entrato"
        # Process exclusions if any
        if [ ${#pattern_not_list[@]} -gt 0 ]; then

            #echo "Exclusion patterns: $pattern_not_list"

            # Use ';;' as the delimiter
            #IFS=';;' read -ra fragments <<< "$PATTERNNOTS"
            IFS=';;' read -ra fragments <<< "$pattern_not_list"
            
            # Remove empty fragments
            local non_empty=()
            for f in "${fragments[@]}"; do
                if [[ -n "$f" ]]; then
                    non_empty+=("$f")
                fi
            done
            fragments=("${non_empty[@]}")
            # Split the PATTERNNOTS list into an array
            # Use ';' as the delimiter
            #local fragments=()
            #IFS=';' read -ra fragments <<< "$PATTERNNOTS"

            #echo "fragments: ${fragments[@]}"

            # Iterate over each exclusion pattern
            for exclude_regex in "${fragments[@]}"; do

                # Replace 'VAR_PLACEHOLDER' literal with $var actual value
                escaped_regex="${exclude_regex//VAR_PLACEHOLDER/$var}"

                # Check if the line matches the exclusion pattern
                echo "$line" | grep -qE "$escaped_regex"
                if [ $? -eq 0 ]; then
                    # If it matches, skip the rule
                    #echo "exclude: $escaped_regex"
                    return
                fi
            done
        fi

        # If the line matches the pattern and does not match any exclusion patterns
        # it means the rule is triggered

        # Add rule index to triggered rules array
        # Needed for report, also in case of --no-rem
        trigger_rule $index $injected_var

        # Read flags by splitting the string by commas
        local flag_list=()
        IFS=',' read -ra flags_list <<< "$vulnerabilities"

        # Set multiple flags
        for flag in "${flags_list[@]}"; do
            set_flag "$flag"
        done
    fi
}

run_detection() {

    local line=$SNIPPET

    # Iterate over the rules
    for index in "${!PATTERNS[@]}"; do

        # Var to be injected (NO_VAR by default)
        local var="NO_VAR"

        # Get the rule details
        local pattern="${PATTERNS[$index]}"
        local pattern_not_list="${PATTERNNOTS[$index]}"
        local find_var="${FINDVARS[$index]}"
        local rule_id="${RULEIDS[$index]}"
        local vulnerabilities="${VULNERABILITIES[$index]}"
        local num_occ=0

        #echo -e "\nfind_var: $find_var"

        # Check if the rule is based on a variable
        if [[ -n "$find_var" ]]; then

            # Count the number of occurrences of the pattern in the line
            num_occ=$(echo "$line" | awk -F "$find_var" '{print NF-1}')
            local i=1

            #echo "# REGOLA"
            #echo "$rule_id"
            #echo -e "\n# occorrenze: $num_occ"

            # For each occurrence
            while [ $i -le $num_occ ]; do

                #var="NO_VAR"

                # Extract the variable name
                var=$(echo "$line" | awk -F "$find_var" -v i="$i" '{print $i}' | awk '{print $NF}')

                # Check if the variable name is empty
                if [ -z "$var" ]; then
                    continue
                else
                    #echo "entrato"
                    # If var is "=", extract previous variable name
                    if [[ "$var" == "=" || "${var: -1}" == "=" ]]; then
                        if [[ "$var" == "=" ]]; then
                            #echo "$i"
                            # Extract the variable name before the "="
                            var=$(echo "$line" | awk -F "$find_var" -v i="$i" '{print $i}' | awk '{print $(NF-1)}')
                            #echo "entrato ="
                        elif [[ "${var: -1}" == "=" ]]; then
                            #echo -e "\nvar: $var"
                            var="${var::-1}"
                        fi
                        
                        #echo -e "\nvar: $var"

                        # Remove last character
                        # last_char="${var: -1}"
                        # var="${var%?}"

                        # Standardize the variable name
                        local new_line=$(echo "$line" | sed -E "
                            s/$var\(/func(/g;
                            s/SELECT $var:?/ /g;
                            s/def $var\(/def func(/g;
                            s/$var *=/ =/g;
                            s/requests\.get\($var\)/requests.get()/g;
                            s/['\"]$var['\"]/ /g;
                            s/requests\.get\(\"$var\", $var/requests.get(/g;
                            # s/$var =\(\)/ /g;
                            s/$var\(\)/ /g;
                            s/int\([ ]*$var/ /g
                        ")

                        # Remove the first occurrence of the pattern
                        # This is done to avoid matching the same pattern again
                        local split=$((i + 1))
                        if [ $num_occ -eq 1 ]; then
                            if [[ "${find_var: -1}" == "[" ]]; then
                                new_line=$(echo "$new_line" | awk -F "$find_var" '{print $2}' | cut -d']' -f$split-)
                            else
                                new_line=$(echo "$new_line" | awk -F "$find_var" '{print $2}' | cut -d')' -f$split-)
                            fi
                        else
                            new_line=$(echo "$new_line" | awk -F "$find_var" -v i="$i" 'NF > i { $1=""; print }' | cut -d')' -f$split-)
                        fi
                    fi
                fi

                # Increment occurencies counter
                i=$((i + 1))

                # Run the standard rule function for each occurrence of the variable
                standard_rule "$new_line" "$pattern" "$pattern_not_list" "$index" "$rule_id" "$vulnerabilities" "$var"

            done


        else
            # If the rule is not based on a variable, run the standard rule function directly
            standard_rule "$line" "$pattern" "$pattern_not_list" "$index" "$rule_id" "$vulnerabilities" "$var"
        fi
    done

    # Increment counter of vulnerable codes
    [ ${#TRIGGERED_RULES[@]} -gt 0 ] && VULN_CODES_COUNTER=$(($VULN_CODES_COUNTER + 1))

}