import os

def delete_files_in_parent_directory(directory):
    try:
        # Get the current directory of the script
        script_directory = os.path.dirname(os.path.realpath(__file__))
        
        # Navigate to the parent directory
        parent_directory = os.path.abspath(os.path.join(script_directory, os.pardir))
        
        # Specify the directory to delete files from (one level up from the script's directory)
        directory_to_delete = os.path.join(parent_directory, directory)
        
        # List all files in the directory
        files = os.listdir(directory_to_delete)
        for file in files:
            file_path = os.path.join(directory_to_delete, file)
            if os.path.isfile(file_path):
                # Delete the file
                os.remove(file_path)
                print(f"Deleted: {file_path}")
        print("All files deleted successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    delete_files_in_parent_directory(r"InfinityGauntlet/C++/InfinityGauntlet/x64/Release/exes")
    delete_files_in_parent_directory(r"InfinityGauntlet/C++/InfinityGauntlet/x64/Release/shellcodes")
