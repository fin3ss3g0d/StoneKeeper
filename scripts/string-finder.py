import glob
import re
import sys

def find_strings_in_cpp_files(directory):
    cpp_files = glob.glob(f"{directory}/*.cpp")

    for file in cpp_files:
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
            strings = re.findall(r'"(.*?)"', content)

            if strings:
                print(f"// {file}")
                for s in strings:
                    if ".hpp" in s:
                        continue
                    # Replace spaces and convert to uppercase
                    upper_no_spaces = s.upper().replace(' ', '')
                    print(f'{{"{upper_no_spaces}_CRYPT", "{s}"}},')
                print()  # Newline for better separation between files

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python string-finder.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    find_strings_in_cpp_files(directory)
