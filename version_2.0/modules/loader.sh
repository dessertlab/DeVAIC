load_rule_from_json() {

    local json_file="$1"

    # Count the number of rules in the JSON file
    local rules_count=$(jq '. | length' "$json_file")

    # For each rule, extract fields
    # For empty fields, set default value "NULL"
    for ((i=0; i<rules_count; i++)); do

        local rule_id=$(jq -r '(.['"$i"'].id // "NULL")' "$json_file")
        RULEIDS+=("$rule_id")

        # No need to load description ...

        local vulnerabilities=$(jq -r ".[$i].vulnerabilities" "$json_file")
        VULNERABILITIES+=("$vulnerabilities")

        local pattern=$(jq -r ".[$i].pattern" "$json_file")
        PATTERNS+=("$pattern")

        local pattern_not=$(jq -r '(.['"$i"'].pattern_not // []) | if length == 0 then "NULL" else join(";") end' "$json_file")
        PATTERNNOTS+=("$pattern_not")

        local find_var=$(jq -r '(.['"$i"'].find_var // "NULL")' "$json_file")
        FINDVARS+=("$find_var")

        local imports=$(jq -r '(.['"$i"'].imports // []) | if length == 0 then "NULL" else join(";") end' "$json_file")
        IMPORTS+=("$imports")

        local comments=$(jq -r '(.['"$i"'].comment // "NULL")' "$json_file")
        COMMENTS+=("$comments")
        

        echo -e "${GREEN}\t\t rule $rule_id loaded successfully!${NC}"

    done

}


load_rules_from_folder () {

    local folder="$1"

    # Check if the folder exists
    if [[ ! -d "$folder" ]]; then
        echo -e "${RED}[LOADER] No ruleset folder named $folder.${NC}"
        exit 1
    fi

    # Iterate over all JSON files in the folder
    echo -e "${BLUE}[LOADER]${NC} Loading rules from ${BLUE}$folder${NC} folder ...${NC}"
    for file in "$folder"/*; do
        if [[ -f "$file" ]]; then
            echo -e "${BLUE}${NC}\t Loading rules from ${BLUE}$file${NC} file ... ${NC}"
            load_rule_from_json "$file"
        fi
    done
    echo -e "${GREEN}\t Rules loading completed!${NC}"
}
