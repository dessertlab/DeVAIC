# --------------------------------------------------------------------- #
#   BLOCK 3: PREPROCESSING
#   - Convert the input file to an inline format
#   - Remove python comments
#   - Run the appropriate preprocessing script
# --------------------------------------------------------------------- #

convert_to_inline() {
    echo -e "${BLUE}[PREPRO]${NC} Converting the input file to an inline format ...${NC}"
    python3 "$SCRIPT_DIR/convertInline.py" "$TMP_FILENAME" "$TMP_FILENAME"
    echo -e "${GREEN}\t Conversion completed!${NC}"
}

remove_comments () {
    local file="$1"
    echo -e "${BLUE}[PREPRO]${NC} Removing comments from the input file ...${NC}"
    python3 "$SCRIPT_DIR/remove_comments.py" "$file"
    echo -e "${GREEN}\t Comments removed!${NC}"
}

run_preprocessing () {
    echo -e "${BLUE}[PREPRO]${NC} Running the preprocessing script ...${NC}"
    local preproc_script="preprocessing.py"
    [ "$NAME_OS" = "Darwin" ] && preproc_script="preprocessing_macos.py"
    python3 "$SCRIPT_DIR/$preproc_script" "$TMP_FILENAME" "$TMP_FILENAME"
    echo -e "${GREEN}\t Script executed!${NC}"
}