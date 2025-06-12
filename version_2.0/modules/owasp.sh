# Function to convert OWASP short code to full string
code_to_full_string() {
    local code="$1"
    case "$code" in
        "INJC") echo "Injection" ;;
        "CRYF") echo "Cryptographic Failures" ;;
        "SECM") echo "Security Misconfiguration" ;;
        "BRAC") echo "Broken Access Control" ;;
        "IDAF") echo "Identification and Authentication Failures" ;;
        "SLMF") echo "Security Logging and Monitoring Failures" ;;
        "INSD") echo "Insecure Design" ;;
        "SSRF") echo "Server-Side Request Forgery" ;;
        "SDIF") echo "Software and Data Integrity Failures" ;;
        *) echo "Unknown" ;;
    esac
}


# Initialize the OWASP counts and flags
# The keys are the short keys for the OWASP categories and the values are the counts of each category.
init_owasp() {
    OWASP_COUNTS=(  
                [INJC]=0 [CRYF]=0 [SECM]=0 [BRAC]=0 [IDAF]=0
                [SLMF]=0 [INSD]=0 [SSRF]=0 [SDIF]=0
             )
    OWASP_FLAGS=(
                    [INJC]=0 [CRYF]=0 [SECM]=0 [BRAC]=0 [IDAF]=0
                    [SLMF]=0 [INSD]=0 [SSRF]=0 [SDIF]=0
                )
}


# Function to clean the flags at the beginning of each iteration
clean_flags() {
    OWASP_FLAGS["INJC"]=0
    OWASP_FLAGS["CRYF"]=0
    OWASP_FLAGS["SECM"]=0
    OWASP_FLAGS["BRAC"]=0
    OWASP_FLAGS["IDAF"]=0
    OWASP_FLAGS["SLMF"]=0 
    OWASP_FLAGS["INSD"]=0
    OWASP_FLAGS["SSRF"]=0
    OWASP_FLAGS["SDIF"]=0
}

# Function to set the flag for a specific OWASP category
# and append the corresponding full string to the vuln list.
# This function is called when a vulnerability is found during the iteration.
set_flag() {

    # Key is the short key for the OWASP category
    local key="$1"

    # If flag is not yet setted
    if [ "${OWASP_FLAGS[$key]}" -eq 0 ]; then

        # Set flag to 1
        OWASP_FLAGS["$key"]=1

        # Append the new vulnerability to the list
        local full_string=$(code_to_full_string "$key")
        VULN_LIST+=("$full_string")

    fi
}



print_owasp_counters() {

    echo -e "\n${BLUE}[OWASP]${NC} Final counters:${NC}\n"

    echo -e "\t\t${CYAN}=================== [OWASP COUNTERS] ==================="
    
    # For each key, so for each OWASP vulnerability
    for key in "${!OWASP_FLAGS[@]}"; do

        # Get full string vulnerability
        category=$(code_to_full_string "$key")

        # Format output
        printf "\t\t${CYAN} -  %-45s : %d\n${NC}" "$category" "${OWASP_COUNTS[$key]}"

    done
    echo -e "\t\t${CYAN}========================================================${NC}"
}



# Function to update the counters for each OWASP category
# This function is called at the end of each iteration
# and updates the counters based on the flags set during the iteration.
update_counters() {
    # For each category
    for key in "${!OWASP_FLAGS[@]}"; do
        # If the flag is set to 1, increment the corresponding counter
        if [ "${OWASP_FLAGS[$key]}" -gt 0 ]; then
            ((OWASP_COUNTS[$key]++))
        fi
    done
}