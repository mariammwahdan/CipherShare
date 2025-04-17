import os
from typing import List

class FileManager:
    def __init__(self, shared_files_path: str):
        self.shared_files_path = shared_files_path
        os.makedirs('shared_files', exist_ok=True)
        self.shared_files = self._load_shared_files()

    def _load_shared_files(self) -> List[str]:
        try:
            if os.path.exists(self.shared_files_path):
                with open(self.shared_files_path, 'r') as f:
                    return [line.strip() for line in f.readlines()]
            return []
        except Exception as e:
            print(f"Error loading shared files: {e}")
            return []

    def save_shared_files(self):
        try:
            with open(self.shared_files_path, 'w') as f:
                for file in self.shared_files:
                    f.write(f"{file}\n")
        except Exception as e:
            print(f"Error saving shared files: {e}")

    def add_file(self, filename: str):
        try:
            base_filename = os.path.basename(filename)
            if base_filename not in self.shared_files:
                self.shared_files.append(base_filename)
                self.save_shared_files()
                print(f"Added {base_filename} to shared files list")
        except Exception as e:
            print(f"Error adding file to shared files: {e}")

    def remove_file(self, filename: str):
        try:
            base_filename = os.path.basename(filename)
            if base_filename in self.shared_files:
                self.shared_files.remove(base_filename)
                self.save_shared_files()
                # Also remove the file from shared_files directory
                file_path = os.path.join('shared_files', base_filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                print(f"Removed {base_filename} from shared files")
        except Exception as e:
            print(f"Error removing file from shared files: {e}")