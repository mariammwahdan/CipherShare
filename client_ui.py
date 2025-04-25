import os
import sys
import time
import threading
from client import FileSharingClient, ClientState

class CipherShareClientUI:
    """Terminal UI for the CipherShare client"""
    
    def __init__(self, server_host='localhost', server_port=5555):
        self.client = FileSharingClient(server_host, server_port)
        self.exit_flag = False
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Print the app header"""
        self.clear_screen()
        print("=" * 60)
        print("                 CIPHERSHARE FILE SHARING                 ")
        print("=" * 60)
        
        # Print login status
        if self.client.state == ClientState.AUTHENTICATED:
            print(f"Logged in as: {self.client.username}")
        elif self.client.state == ClientState.CONNECTED:
            print("Connected to server (not logged in)")
        else:
            print("Not connected to server")
        print("-" * 60)
    
    def print_menu(self, options):
        """Print a menu with options"""
        for i, option in enumerate(options, 1):
            print(f"{i}. {option}")
        print("0. Exit")
        print("-" * 60)
    
    def get_choice(self, max_choice):
        """Get a valid choice from the user"""
        while True:
            try:
                choice = input("Enter your choice: ")
                choice = int(choice)
                if 0 <= choice <= max_choice:
                    return choice
                print(f"Please enter a number between 0 and {max_choice}")
            except ValueError:
                print("Please enter a valid number")
    
    def wait_for_key(self):
        """Wait for the user to press a key"""
        input("\nPress Enter to continue...")
    
    def show_auth_menu(self):
        """Show the authentication menu"""
        while not self.exit_flag:
            self.print_header()
            self.print_menu(["Register", "Login", "Connect to server"])
            
            choice = self.get_choice(3)
            
            if choice == 0:
                self.exit_flag = True
            elif choice == 1:
                self.register_user()
            elif choice == 2:
                self.login_user()
            elif choice == 3:
                self.connect_to_server()
            
            if self.client.state == ClientState.AUTHENTICATED:
                break
    
    def register_user(self):
        """Register a new user"""
        self.print_header()
        print("REGISTER NEW USER")
        print("-" * 60)
        
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        print("\nRegistering, please wait...")
        success, message = self.client.register(username, password)
        
        print(message)
        self.wait_for_key()
    
    def login_user(self):
        """Login with username and password"""
        self.print_header()
        print("LOGIN")
        print("-" * 60)
        
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        print("\nLogging in, please wait...")
        success, message = self.client.login(username, password)
        
        print(message)
        self.wait_for_key()
    
    def connect_to_server(self):
        """Connect to the server"""
        self.print_header()
        print("CONNECTING TO SERVER")
        print("-" * 60)
        
        print("Connecting, please wait...")
        if self.client.connect_to_server():
            print("Connected successfully")
        else:
            print("Failed to connect to server")
        
        self.wait_for_key()
    
    def show_main_menu(self):
        """Show the main menu"""
        while not self.exit_flag:
            # Check if session is still valid
            if self.client.state == ClientState.AUTHENTICATED and not self.client.check_session():
                print("Your session has expired. Please login again.")
                self.wait_for_key()
                self.show_auth_menu()
                if self.exit_flag:
                    break
                continue
            
            self.print_header()
            
            options = [
                "Upload a file",
                "Download a file",
                "List available files",
                "List my shared files",
                "Remove a shared file",
            ]
            
            if self.client.state == ClientState.AUTHENTICATED:
                options.append("Disconnect")
            elif self.client.state == ClientState.CONNECTED:
                options.append("Login")
                options.append("Register new account")
            else:
                options.append("Connect to server")
            
            self.print_menu(options)
            
            choice = self.get_choice(len(options))
            
            if choice == 0:
                self.exit_flag = True
            elif choice == 1:
                self.upload_file()
            elif choice == 2:
                self.download_file()
            elif choice == 3:
                self.list_available_files()
            elif choice == 4:
                self.list_shared_files()
            elif choice == 5:
                self.remove_shared_file()
            elif choice == 6:
                if self.client.state == ClientState.AUTHENTICATED:
                    self.disconnect()
                elif self.client.state == ClientState.CONNECTED:
                    self.login_user()
                else:
                    self.connect_to_server()
            elif choice == 7 and self.client.state == ClientState.CONNECTED:
                self.register_user()
    
    def upload_file(self):
        """Upload (share) a file"""
        if self.client.state != ClientState.AUTHENTICATED:
            print("You need to login first")
            self.wait_for_key()
            return
        
        self.print_header()
        print("UPLOAD A FILE")
        print("-" * 60)
        
        file_path = input("Enter the path to the file: ")
        
        if not os.path.isfile(file_path):
            print(f"File '{file_path}' not found")
            self.wait_for_key()
            return
        
        print("\nUploading, please wait...")
        success, message = self.client.upload_file(file_path)
        
        print(message)
        self.wait_for_key()
    
    def download_file(self):
        """Download a file"""
        if self.client.state != ClientState.AUTHENTICATED:
            print("You need to login first")
            self.wait_for_key()
            return
        
        self.print_header()
        print("DOWNLOAD A FILE")
        print("-" * 60)
        
        # Get available files
        success, message, files = self.client.list_files()
        
        if not success or not files:
            print("No files available for download")
            self.wait_for_key()
            return
        
        print("Available files:")
        for i, file_info in enumerate(files, 1):
            print(f"{i}. {file_info['filename']} (by {file_info['owner']})")
        
        try:
            choice = int(input("\nEnter the number of the file to download (0 to cancel): "))
            if choice == 0:
                return
            if 1 <= choice <= len(files):
                filename = files[choice - 1]['filename']
                
                print(f"\nDownloading '{filename}', please wait...")
                success, message = self.client.download_file(filename)
                
                print(message)
            else:
                print("Invalid choice")
        except ValueError:
            print("Please enter a valid number")
        
        self.wait_for_key()
    
    def list_available_files(self):
        """List files available for download"""
        if self.client.state != ClientState.AUTHENTICATED:
            print("You need to login first")
            self.wait_for_key()
            return
        
        self.print_header()
        print("AVAILABLE FILES")
        print("-" * 60)
        
        success, message, files = self.client.list_files()
        
        if success and files:
            print(f"Found {len(files)} available files:")
            for i, file_info in enumerate(files, 1):
                print(f"{i}. {file_info['filename']} (by {file_info['owner']})")
        else:
            print("No files available for download")
        
        self.wait_for_key()
    
    def list_shared_files(self):
        """List files being shared by this client"""
        self.print_header()
        print("MY SHARED FILES")
        print("-" * 60)
        
        if not self.client.shared_files:
            print("You are not sharing any files")
        else:
            print(f"You are sharing {len(self.client.shared_files)} files:")
            for i, filename in enumerate(self.client.shared_files, 1):
                print(f"{i}. {filename}")
        
        self.wait_for_key()
    
    def remove_shared_file(self):
        """Remove a file from sharing"""
        if self.client.state != ClientState.AUTHENTICATED:
            print("You need to login first")
            self.wait_for_key()
            return
        
        self.print_header()
        print("REMOVE SHARED FILE")
        print("-" * 60)
        
        if not self.client.shared_files:
            print("You are not sharing any files")
            self.wait_for_key()
            return
        
        print("Your shared files:")
        for i, filename in enumerate(self.client.shared_files, 1):
            print(f"{i}. {filename}")
        
        try:
            choice = int(input("\nEnter the number of the file to remove (0 to cancel): "))
            if choice == 0:
                return
            if 1 <= choice <= len(self.client.shared_files):
                filename = self.client.shared_files[choice - 1]
                
                print(f"\nRemoving '{filename}', please wait...")
                success, message = self.client.remove_file(filename)
                
                print(message)
            else:
                print("Invalid choice")
        except ValueError:
            print("Please enter a valid number")
        
        self.wait_for_key()
    
    def disconnect(self):
        """Disconnect from the server"""
        self.print_header()
        print("DISCONNECTING")
        print("-" * 60)
        
        print("Disconnecting, please wait...")
        success, message = self.client.disconnect()
        
        print(message)
        self.wait_for_key()
    
    def run(self):
        """Run the client UI"""
        try:
            # Try to connect first
            if not self.client.reconnect()[0]:
                self.connect_to_server()
                
            # After connecting, show main menu even without authentication
            # The main menu will have login and register options if not authenticated
            self.show_main_menu()
            
            # Disconnect on exit
            if self.client.state != ClientState.DISCONNECTED:
                print("\nDisconnecting from server...")
                self.client.disconnect()
            
            print("\nThank you for using CipherShare!")
        except KeyboardInterrupt:
            print("\n\nExiting CipherShare...")
            if self.client.state != ClientState.DISCONNECTED:
                self.client.disconnect()
            sys.exit(0)


def main():
    """Main function to start the client UI"""
    # Get server address from command line arguments
    server_host = 'localhost'
    server_port = 5555
    
    if len(sys.argv) > 1:
        server_host = sys.argv[1]
    if len(sys.argv) > 2:
        server_port = int(sys.argv[2])
    
    ui = CipherShareClientUI(server_host, server_port)
    ui.run()


if __name__ == "__main__":
    main()