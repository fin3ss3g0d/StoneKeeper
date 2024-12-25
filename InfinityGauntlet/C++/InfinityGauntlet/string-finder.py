import glob
import re

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
                    print(f'{{"{s.upper().replace(' ', '')}_CRYPT", "{s}"}},')
                print()  # Newline for better separation between files

if __name__ == "__main__":
    current_directory = "."  # Current directory
    find_strings_in_cpp_files(current_directory)
