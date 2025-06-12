# Function to print the table header
# This function is called at the beginning of the detection process
print_table_header() {
    local line=$(printf '%0.s=' {1..190})
    echo -e "\n${BLUE}${line}${NC}"
    printf "${BLUE}| ${CYAN}%-4s${BLUE} | ${CYAN}%-34s${BLUE} | ${CYAN}%-65s${BLUE} | ${CYAN}%-5s${BLUE} | ${CYAN}%-65s${BLUE} |\n${NC}" \
        "INDEX" "RULE_ID" "PATTERN" "MATCH" "ESCAPE"
    echo -e "${BLUE}${line}${NC}"
}

# Function to print a separator line
# This function is called between each rule in the table
print_table_separator() {
    local line
    line=$(printf '%0.s-' {1..190})
    echo -e "${BLUE}${line}${NC}"
}

# Function to print the table footer
# This function is called at the end of the detection process
print_table_footer() {
    local line
    line=$(printf '%0.s=' {1..190})
    echo -e "${BLUE}${line}${NC}\n"
}

# Function to print a row in the table
# This function is called for each rule in the detection process
print_table_row() {
    local index="$1"
    local rule_id="$2"
    local pattern="$3"
    local match="$4"
    local escape="$5"

    # Set color based on match status
    local color_match="${NC}"
    [[ "$match" == "TRUE" && "$escape" != "NOT_TRIGGERED" ]] && color_match="${RED}"
    [[ "$match" == "FALSE" ]] && color_match="${GREEN}"

    # Set color for escape
    local color_escape="${NC}"
    [[ "$match" == "TRUE" && "$escape" == "NOT TRIGGERED" ]] && color_escape="${RED}"
    [[ "$match" == "TRUE" && "$escape" != "NOT TRIGGERED" ]] && color_escape="${GREEN}"

    printf "${BLUE}|${NC} %-5s ${BLUE}|${NC} %-34s ${BLUE}|${NC} %-65s ${BLUE}|${NC} ${color_match}%-5s${NC} ${BLUE}|${NC}${color_escape} %-65s ${BLUE}|${NC}\n" \
        "$index" "$rule_id" "$pattern" "$match" "$escape"
}
