
import sys
import os

def convert_to_single_line(input_file, output_file):
    try:
        #controlla se il file esiste
        if not os.path.exists(input_file):
            print(f"Il file '{input_file}' non esiste.")
            return
        
        # Legge il contenuto del file sorgente
        with open(input_file, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Rimuove i caratteri di nuova riga
        single_line_content = content.replace("\n","\\n ")
        
        # Salva il contenuto risultante in un nuovo file
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(single_line_content)
        
    except Exception as e:
        pass


# Esempio di utilizzo
source_file = sys.argv[1]  # Inserisci il nome del file sorgente

target_file = sys.argv[2]  # Inserisci il nome del file di destinazione

convert_to_single_line(source_file, target_file)