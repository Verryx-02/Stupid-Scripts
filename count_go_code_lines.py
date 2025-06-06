import os

def count_go_code_lines(folder_path: str) -> int:
    total_lines = 0
    for dirpath, _, filenames in os.walk(folder_path):
        for filename in filenames:
            if filename.endswith(".go"):
                file_path = os.path.join(dirpath, filename)
                total_lines += count_lines_in_file(file_path)
    return total_lines

def count_lines_in_file(file_path: str) -> int:
    count = 0
    in_block_comment = False

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            stripped = line.strip()

            # Gestione dei commenti multilinea
            if in_block_comment:
                if '*/' in stripped:
                    in_block_comment = False
                    stripped = stripped.split('*/', 1)[1].strip()
                    if not stripped:
                        continue
                else:
                    continue

            while '/*' in stripped:
                pre_comment, post_comment = stripped.split('/*', 1)
                if '*/' in post_comment:
                    # Commento su una sola riga
                    post_comment = post_comment.split('*/', 1)[1]
                    stripped = (pre_comment + post_comment).strip()
                else:
                    # Commento su più righe
                    in_block_comment = True
                    stripped = pre_comment.strip()
                    break

            # Salta righe vuote o con commenti a singola linea
            if not stripped or stripped.startswith('//'):
                continue

            count += 1
    return count

# Esecuzione da terminale
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Uso: python count_go_code_lines.py /percorso/della/cartella")
    else:
        folder = sys.argv[1]
        total = count_go_code_lines(folder)
        print(f"Totale righe di codice Go (escludendo commenti e righe vuote): {total}")