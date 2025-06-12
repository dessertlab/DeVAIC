#!/bin/bash

# --------------------------------------------------------------------- #
#   BLOCK 0: GLOBAL VARIABLES                                           #
#   - Global variables are represented in uppercase                     # 
# --------------------------------------------------------------------- #

# Timestamps variables.
# Those are used to measure execution time of each functional block of code.
START=""
START_CONFIG=""
START_PREPROCESS=""
START_LOADER=""
START_CORE=""
START_SNIPPET_EXEC_TIME=""
RUNTIME=""

# Option variables (set to false by default).
# Those are setted if any option is specified by command line arguments.
MULTI=false
VERBOSE=false

# Positional arguments array.
# This script requires two positional arguments
# (1 = input path, 2 = script's source directory)
POSITIONAL_ARGS=()

# Command line arguments variables
INPUT_PATH=""   # Will be first positional argument
TOOL_DIR=""     # Will be second positional argument

# Other configuration variables (set from config.sh)
NAME_OS=""              # OS detected name
INPUT_FILENAME=""       # Input file's name
JSON_OUTPUT_FILENAME="" # JSON output file's name
CSV_OUTPUT_FILENAME=""  # CSV output file's name (for --verbose)
SRC_DIR=""              # Working directory
SCRIPT_DIR=""           # Python scripts directory
RES_DIR=""              # Results directory

# This is temporary file used for preprocessing pipeline.
# It is set by config.sh and will be initialized as a copy of the input file.
TMP_FILENAME=""

# Values for final statistics
VULN_CODES_COUNTER=0
VULNERABILIY_RATE=0

# Dictionary for OWASP mapping (global counters).
# This dictionary is used to store the counts of each OWASP category and is used to generate the final report.
declare -A OWASP_COUNTS

# Dictionary for OWASP mapping (iteration flags).
# This dictionary is used to track if a vulnerability was found during the iteration on a snippet of code.
declare -A OWASP_FLAGS

# Arrays used to store rules' informations read from the ruleset.
# Use of _ means an inner field of the JSON object.
declare -a RULEIDS=()
declare -a VULNERABILITIES=()
declare -a PATTERNS=()
declare -a PATTERNNOTS=()
declare -a FINDVARS=()
declare -a IMPORTS=()
declare -a COMMENTS=()
declare -a REMEDIATION_SOURCES=()
declare -a REMEDIATION_REPLACEMENTS=()

# Array used to store vulnerabilities found during the iteration.
# It is used to generate the final report.
declare -a VULN_LIST=()

# Array that stores indexes of triggered rules.
# Those indexes are valid for each array (patterns, rule_ids, etc.).
declare -a TRIGGERED_RULES=()

# Array that stores variables to be injected in the remediation phase.
# If no var has to be injected, "NO_VAR" palceholder is stored for that index.
declare -a INJECTED_VARS=()


# --------------------------------------------------------------------- #
#   BLOCK 1: DeVAIC STARTER                                             #
#   - Initialize option variables                                       #
#   - Parse command line arguments                                      #
#   - Check required positional arguments                               #
#   - Assign positional arguments to variables                          #
#   - Set options if provided                                           #
# --------------------------------------------------------------------- #

# Timestamp: script started
START=$(date +%s.%N)

# Text color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
ORANGE='\e[38;2;255;165;0m'
CYAN='\033[0;36m'
NC='\033[0m'

# ASCII art - DeVAIC
echo -e "\n${GREEN}\n"
echo -e "\t██████╗ ███████╗██╗   ██╗ █████╗ ██╗ ██████╗"
echo -e "\t██╔══██╗██╔════╝██║   ██║██╔══██╗██║██╔════╝"
echo -e "\t██║  ██║█████╗  ██║   ██║███████║██║██║     "
echo -e "\t██║  ██║██╔══╝  ╚██╗ ██╔╝██╔══██║██║██║     "
echo -e "\t██████╔╝███████╗ ╚████╔╝ ██║  ██║██║╚██████╗"
echo -e "\t╚═════╝ ╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚═╝ ╚═════╝"
echo -e "\n\n${NC}"

echo -e "${BLUE}[DeVAIC]${NC} Detection of Vulnerabilities in AI-generated Code\n${NC}"

# Color legend
echo -e "${BLUE}[DeVAIC]${NC} Color legend${NC}"
echo -e "\t ${BLUE}Blue${NC}\t - Information message"
echo -e "\t ${GREEN}Green${NC}\t - Successful operation"
echo -e "\t ${YELLOW}Yellow${NC}\t - Warning message"
echo -e "\t ${RED}Red${NC}\t - Error message"
echo -e "\t ${PURPLE}Purple${NC}\t - Timing message\n"

# Function to show help message
show_help_message() {
    echo -e "${BLUE}[DeVAIC]${NC} Usage: $0 <path1> <path2> [options]"
    echo -e "\t Please provide the path to the input file and the installation path of the tool."
    echo -e "\t Example: $0 /path/to/input_file /path/to/installation"
    echo -e "\t Options:"
    echo -e "\t\t --multi      Run from a file with multiple inline code snippets"
    echo -e "\t\t --help       Show this help message\n"
}

# Parse command line arguments
# Use shift to remove the processed argument from the list
for ARG in "$@"; do
    case $ARG in
        --multi)    MULTI=true  && shift ;;
        --verbose)  VERBOSE=true && shift ;;
        --help)     show_help_message && exit 0 ;;
        -*)         echo -e "${RED}[DeVAIC] Unknown option: $ARG${NC}" && exit 1 ;;
        *)          POSITIONAL_ARGS+=("$ARG") && shift ;;
    esac
done

# Check required positional arguments
if [ "${#POSITIONAL_ARGS[@]}" -lt 2 ]; then
    show_help_message
    exit 1
fi

echo -e "${BLUE}[DeVAIC]${NC} Tool is running ...\n${NC}"

# Assign positional arguments to variables
INPUT_PATH="${POSITIONAL_ARGS[0]}"
TOOL_DIR="${POSITIONAL_ARGS[1]}"

# Load modules
source $TOOL_DIR/modules/config.sh          # Import configuration function
source $TOOL_DIR/modules/preprocess.sh      # Import preprocessing scripts
source $TOOL_DIR/modules/loader.sh          # Import rule loading functions
source $TOOL_DIR/modules/owasp.sh           # Import OWASP counters and flags' manipulation functions
source $TOOL_DIR/modules/detector.sh        # Import detection engine
source $TOOL_DIR/modules/writer.sh          # Import writer function (json and csv output)

# Print provided options
[ $MULTI = true ] && echo -e "${YELLOW}[DeVAIC]${NC} Multi-snippet mode enabled.\n${NC}"
[ $VERBOSE = true ] && echo -e "${YELLOW}[DeVAIC]${NC} Verbose mode enabled.\n${NC}"

echo -e "\n${BLUE}-------------------------------------------------------------------------------${NC}\n"


# --------------------------------------------------------------------- #
#   BLOCK 2: CONFIGURATION                                              #
# --------------------------------------------------------------------- #

START_CONFIG=$(date +%s.%N)

# Run configuration routine
config

RUNTIME=$(python3 -c "import time; print(f'{time.time() - $START_CONFIG:.4f}')")
echo -e "\n${PURPLE}[DeVAIC]${NC} CONFIG runtime: ${PURPLE}$RUNTIME s${NC}\n"

echo -e "\n${BLUE}-------------------------------------------------------------------------------${NC}\n"


# --------------------------------------------------------------------- #
#   BLOCK 3: PREPROCESSING                                              # 
# --------------------------------------------------------------------- #

START_PREPROCESS=$(date +%s.%N)

# Avoid some processing if the input is already in the correct format
[[ $MULTI == false ]]  && remove_comments "$TMP_FILENAME" && convert_to_inline "$TMP_FILENAME"

# Run the preprocessing script
run_preprocessing

RUNTIME=$(python3 -c "import time; print(f'{time.time() - $START_PREPROCESS:.4f}')")
echo -e "\n${PURPLE}[DeVAIC]${NC} PREPROCESS runtime: ${PURPLE}$RUNTIME s${NC}\n"

echo -e "\n${BLUE}-------------------------------------------------------------------------------${NC}\n"


# --------------------------------------------------------------------- #
#   BLOCK 4: LOADER                                                     #
# --------------------------------------------------------------------- #

START_LOADER=$(date +%s.%N)

# Load rules from the ruleset folder
#load_rules_from_folder $TOOL_DIR/ruleset_tmp
load_rules_from_folder $TOOL_DIR/ruleset

RUNTIME=$(python3 -c "import time; print(f'{time.time() - $START_LOADER:.4f}')")
echo -e "\n${PURPLE}[DeVAIC]${NC} LOADER runtime: ${PURPLE}$RUNTIME s${NC}\n"

echo -e "\n${BLUE}-------------------------------------------------------------------------------${NC}\n"


# --------------------------------------------------------------------- #
#   BLOCK 5: CORE ENGINE (DETECTOR, PATCHER*, WRITER)                   #
#   * PATCHER can be diasbled by running this script in --no-rem mode   #
# --------------------------------------------------------------------- #

START_CORE=$(date +%s.%N)

# Initialize OWASP counters and flags
init_owasp

# Read the input file line by line
mapfile -t CODES < "$TMP_FILENAME"

# Initialize the snippet count
# This will be used to track the current snippet being processed
SNIPPET_COUNT=1

# Initialize output file (open JSON array)
echo "[" >> $JSON_OUTPUT_FILENAME

# If --verbose, write CSV header
[ $VERBOSE = true ] && write_csv_header

# Loop through each code snippet
for SNIPPET in "${CODES[@]}"; do

    # Begin
    START_SNIPPET_EXEC_TIME=$(date +%s.%N)

    # Run the detection function on the current snippet
    echo -e "${BLUE}[DeVAIC]${NC} Running detection on line $SNIPPET_COUNT ...${NC}"
    run_detection 2> /dev/null

    # Update counters
    update_counters

    # Mesure execution time for this snippet
    SNIPPET_EXEC_TIME=$(python3 -c "import time; print(f'{time.time() - $START_SNIPPET_EXEC_TIME:.4f}')")

    # Write partial results to the output file
    write_json

    # If --verbose, write a CSV line
    [ $VERBOSE = true ] && write_csv_row

    # Clean up the flags for the next iteration
    clean_flags

    # Clean arrays
    TRIGGERED_RULES=()
    INJECTED_VARS=()
    VULN_LIST=()

    # Increment the snippet count
    SNIPPET_COUNT=$((SNIPPET_COUNT + 1))

done

# Close output file (close JSON array)
echo "]" >> $JSON_OUTPUT_FILENAME

# Print results
print_owasp_counters

# Print statistics
if [ ${#CODES[@]} -eq 0 ]; then
    VULNERABILITY_RATE="N/A"
else
    VULNERABILITY_RATE=$(echo "scale=2; ($VULN_CODES_COUNTER / ${#CODES[@]}) * 100" | bc)
fi
echo -e "\n${BLUE}[DeVAIC]${NC} Dataset size: ${#CODES[@]}"
echo -e "${BLUE}[DeVAIC]${NC} Vulnerable codes: $VULN_CODES_COUNTER"
echo -e "${BLUE}[DeVAIC]${NC} Vulnerability rate: $VULNERABILITY_RATE %\n"


RUNTIME=$(python3 -c "import time; print(f'{time.time() - $START_CORE:.4f}')")
echo -e "\n${PURPLE}[DeVAIC]${NC} CORE ENGINE runtime: ${PURPLE}$RUNTIME s${NC}\n"

echo -e "\n${BLUE}-------------------------------------------------------------------------------${NC}\n"


# --------------------------------------------------------------------- #
#   BLOCK 6: TEARDOWN                                                   #
#   - Clean up the generated files                                      #
#   - Print final messages and timestamp                                #
# --------------------------------------------------------------------- #

echo -e "${BLUE}[DeVAIC]${NC} Teardown phase ...\n${NC}"

# Clean up the generated files
echo -e "${BLUE}[DeVAIC]${NC} Cleaning up generated files ...${NC}"

# Remove the temporary file
rm -f "$TMP_FILENAME"
echo -e "\t Removed ${BLUE}$TMP_FILENAME\n${NC}"

# Print the final messages and timestamp
echo -e "${BLUE}[DeVAIC]${NC} DeVAIC has finished running!${NC}"
echo -e "${BLUE}[DeVAIC]${NC} Hope to see you soon!${NC}"

RUNTIME=$(python3 -c "import time; print(f'{time.time() - $START:.4f}')")
echo -e "\n${PURPLE}[DeVAIC]${NC} Runtime: ${PURPLE}$RUNTIME s${NC}\n"