# --------------------------------------------------------------------- #
#   BLOCK 2: CONFIGURATION
#   - Get the OS name
#   - Extract file name and path
#   - Generate temporary file used for the pipeline
#   - Set directories
#   - Create generated file directory if it doesn't exist
#   - Create results directory
#   - Generate output file
#   - Adjust PATH for macOS if needed
#   - Print config informations
# --------------------------------------------------------------------- #

config () {

    # Get the OS name
    NAME_OS=$(uname)

    # Extract file name and path
    FILENAME=$(basename "$INPUT_PATH")
    SRC_DIR=$(dirname "$INPUT_PATH")

    # Generate temporary file used for the pipeline
    local nameWithoutType="${FILENAME%.*}"
    TMP_FILENAME="$SRC_DIR/TMP_${nameWithoutType}.txt"
    cp "$INPUT_PATH" "$TMP_FILENAME"

    # Set directories
    SCRIPT_DIR="$TOOL_DIR/script_py"
    RES_DIR="$TOOL_DIR/results"

    # Create results directory
    mkdir -p "$RES_DIR"
    echo -e "${BLUE}[CONFIG]${NC} Creating directory $RES_DIR ...${NC}"
    echo -e "${GREEN}\t $RES_DIR created!${NC}"

    # Generate JSON output file
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    JSON_OUTPUT_FILENAME="$RES_DIR/[$timestamp]_${nameWithoutType}.json"
    echo -e "${BLUE}[CONFIG]${NC} Creating output file $JSON_OUTPUT_FILENAME ...${NC}"
    touch "$JSON_OUTPUT_FILENAME"
    echo -e "${GREEN}\t $JSON_OUTPUT_FILENAME created!${NC}"

    # Generate CSV output file (only for --verbose)
    if [ $VERBOSE = true ]; then
        CSV_OUTPUT_FILENAME="$RES_DIR/[$timestamp]_${nameWithoutType}.csv"
        echo -e "${BLUE}[CONFIG]${NC} Creating output file $CSV_OUTPUT_FILENAME ...${NC}"
        touch "$CSV_OUTPUT_FILENAME"
        echo -e "${GREEN}\t $CSV_OUTPUT_FILENAME created!${NC}"
    fi

    # Adjust PATH for macOS if needed
    if [ "$NAME_OS" = "Darwin" ]; then
        for p in "/opt/homebrew/opt/grep/libexec/gnubin" "/usr/local/opt/grep/libexec/gnubin"; do
            if [ -d "$p" ] && [[ ":$PATH:" != *":$p:"* ]]; then
                export PATH="$p:$PATH"
                echo -e "${BLUE}[CONFIG]${NC} Added $p to PATH${NC}"
                break
            fi
        done
    fi

    # Print config informations
    echo -e "\n${BLUE}[CONFIG]${NC} OS name: ${BLUE}$NAME_OS${NC}"
    echo -e "${NC}\t File name: ${BLUE}$FILENAME${NC}"
    echo -e "${NC}\t Source directory: ${BLUE}$SRC_DIR${NC}"
    echo -e "${NC}\t Temporary file: ${BLUE}$TMP_FILENAME${NC}"
    echo -e "${NC}\t Tool directory: ${BLUE}$TOOL_DIR${NC}"
    echo -e "${NC}\t Script directory: ${BLUE}$SCRIPT_DIR${NC}"
    echo -e "${NC}\t Results directory: ${BLUE}$RES_DIR${NC}"
    echo -e "${NC}\t JSON output file: ${BLUE}$JSON_OUTPUT_FILENAME${NC}"
    [ $VERBOSE = true ] && echo -e "${NC}\t CSV output file: ${BLUE}$CSV_OUTPUT_FILENAME${NC}"
    echo -e "\n"

}