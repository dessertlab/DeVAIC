import sys
import regex as re  # <--- usa 'regex' invece di 're'

def remove_comments(code: str) -> str:
    # Rimuove docstring """ """ e ''' ''' che NON sono parte di assegnazioni
    code = re.sub(r'(?<![=:\(\[\{]\s*)(?P<quote>["\']{3})(?:.|[\r\n])*?(?P=quote)', '', code)

    # Rimuove i commenti singoli #
    code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)

    return code

if __name__ == "__main__":
    code_file = sys.argv[1]

    # Leggi il file
    with open(code_file, 'r', encoding='utf-8') as f:
        code = f.read()

    # Pulisci il codice
    cleaned_code = remove_comments(code)

    # Sovrascrive il file originale
    with open(code_file, 'w', encoding='utf-8') as f:
        f.write(cleaned_code)