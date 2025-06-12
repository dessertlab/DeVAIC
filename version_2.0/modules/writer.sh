# Function used to generate partial json report
write_json() {

    # Open JSON object
    echo -n "    {" >> $JSON_OUTPUT_FILENAME

    # Check if vulnerable
    local vulnerable=false
    [[ ${#VULN_LIST[@]} -gt 0 ]] && vulnerable=true

    # Represent bash list as a JSON list
    local vulnerabilities=""
    for vuln in "${VULN_LIST[@]}"; do
        vulnerabilities+="\""
        vulnerabilities+=$vuln
        vulnerabilities+="\", "
    done

    # Remove trailing , and space
    vulnerabilities=$(echo "$vulnerabilities" | sed 's/, $//')

    # Load comments and imports
    local comments=""
    local imports=""


    # Start printing summary fields
    echo -n "
        \"snippet_number\": $SNIPPET_COUNT,
        \"original_code\": $(python3 -c "import sys, json; print(json.dumps(sys.argv[1]))" "$SNIPPET"),
        \"vulnerable\": $vulnerable,
        \"vulnerabilities_summary\": [$vulnerabilities],
        \"comments\": [$comments],
        \"execution_time\": \"$SNIPPET_EXEC_TIME\"," >> $JSON_OUTPUT_FILENAME


    write_json_details

    # Close JSON object (add a comma if it's not the last snippet)
    echo -n "
    }" >> $JSON_OUTPUT_FILENAME
    echo $( [[ $SNIPPET_COUNT -lt ${#CODES[@]} ]] && echo ',' || echo '') >> $JSON_OUTPUT_FILENAME

}


# Function used to iterate over triggered rules and print details in the output file
write_json_details() {

    echo -n "
        \"details\": [" >> $JSON_OUTPUT_FILENAME

    for i in "${!TRIGGERED_RULES[@]}"; do

        local rule_index="${TRIGGERED_RULES[$i]}"

        # Extract details of the triggered rule from respective arrays
        local rule_id="${RULEIDS[$rule_index]}"
        local vulnerabilities="${REMEDIATION_VULNERABILITIES[$rule_index]}"
        local comment="${COMMENTS[$rule_index]}"
        
        # Split flag list on commas
        local flag_list=()
        IFS=',' read -ra flag_list <<< "$vulnerabilities"
        
        # Build a JSON list
        vulnerabilities=""
        for flag in "${flags_list[@]}"; do
            vulnerabilities+="\""
            vulnerabilities+=$(code_to_full_string $flag)
            vulnerabilities+="\", "
        done

        # Remove trailing , and space
        vulnerabilities=$(echo "$vulnerabilities" | sed 's/, $//')

        # Write JSON object in a variable
        echo -n "
            {
                \"rule_id\": \"$rule_id\",
                \"vulnerabilities\": [$vulnerabilities],
                \"comment\": \"$comment\"" >> $JSON_OUTPUT_FILENAME

            echo -n "
            }" >> $JSON_OUTPUT_FILENAME
        
        
        # Check if this is not the last rule in the array, then print a comma
        if [[ $i -lt $((${#TRIGGERED_RULES[@]} - 1)) ]]; then
            echo -n "," >> $JSON_OUTPUT_FILENAME
        fi

    done

    echo "
        ]" >> $JSON_OUTPUT_FILENAME
}


# Write header of CSV output file
write_csv_header() {

    # Snippet number field
    echo -n "SNIPPET_NUMBER" >> $CSV_OUTPUT_FILENAME

    # A field for each each OWASP category
    for key in "${!OWASP_FLAGS[@]}"; do
        echo -n ",$key" >> $CSV_OUTPUT_FILENAME
    done

    # A field for each rule
    for rule in "${RULEIDS[@]}"; do
        echo -n ",$rule" >> $CSV_OUTPUT_FILENAME
    done

    # Carriage return
    echo >> $CSV_OUTPUT_FILENAME
}

# Function to write a CSV line
write_csv_row() {

    # Write snippet number
    echo -n "$SNIPPET_COUNT" >> $CSV_OUTPUT_FILENAME

    # Write flag values (0 or 1, in the same order of the header)
    for key in "${!OWASP_FLAGS[@]}"; do
        echo -n ",${OWASP_FLAGS[$key]}" >> "$CSV_OUTPUT_FILENAME"
    done

    # Write 0 if a rule is not triggered, or 1 it is
    for i in "${!RULEIDS[@]}"; do
        local found=0
        # If index in triggered rules corresponds to this rule_id's index,
        # stop searching and write 1. Otherwise, 0 will be written
        for t in "${TRIGGERED_RULES[@]}"; do
            if [[ "$t" -eq "$i" ]]; then
                found=1
                break
            fi
        done
        echo -n ",$found" >> $CSV_OUTPUT_FILENAME
    done

    # Carriage return
    echo >> $CSV_OUTPUT_FILENAME
}