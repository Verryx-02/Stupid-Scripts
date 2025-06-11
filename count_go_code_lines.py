import os

def analyze_go_file(file_path: str) -> tuple[int, int, int, int]:
    total = 0
    comment = 0
    empty = 0
    code = 0
    in_block_comment = False

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            total += 1
            stripped = line.strip()

            if not stripped:
                empty += 1
                continue

            if in_block_comment:
                comment += 1
                if '*/' in stripped:
                    in_block_comment = False
                    if stripped.endswith('*/'):
                        continue
                    else:
                        # There is code after the comment closes
                        remaining = stripped.split('*/', 1)[1].strip()
                        if remaining and not remaining.startswith('//'):
                            code += 1
                continue

            if stripped.startswith('//'):
                comment += 1
                continue

            if '/*' in stripped:
                comment += 1
                if '*/' in stripped:
                    continue  # In-line comment
                else:
                    in_block_comment = True
                continue

            code += 1

    return total, comment, empty, code

def analyze_go_folder(folder_path: str) -> tuple[int, int, int, int]:
    total_lines = 0
    comment_lines = 0
    empty_lines = 0
    code_lines = 0

    for dirpath, _, filenames in os.walk(folder_path):
        for filename in filenames:
            if filename.endswith(".go"):
                file_path = os.path.join(dirpath, filename)
                total, comment, empty, code = analyze_go_file(file_path)
                total_lines += total
                comment_lines += comment
                empty_lines += empty
                code_lines += code

    return total_lines, comment_lines, empty_lines, code_lines

# Execution from terminal
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Uso: python count_go_code_lines.py /percorso/della/cartella")
    else:
        folder = sys.argv[1]
        total, comment, empty, code = analyze_go_folder(folder)
        print(f"Totale righe nei file Go: {total}")
        print(f"Righe di commento: {comment}")
        print(f"Righe vuote: {empty}")
        print(f"Righe di codice Go (escludendo commenti e righe vuote): {code}")
