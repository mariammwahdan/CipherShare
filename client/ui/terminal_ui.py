from core.client import Client
from utils.enums import ClientState


class ClientUI:
    def __init__(self, client: Client):
        self.client = client
        self.running = True

    def display_menu(self):
        print("\n=== CipherShare Client ===")
        print("1. Upload File")
        print("2. Download File")
        print("3. List Available Files")
        print("4. Remove Shared File")
        print("5. Disconnect" if self.client.state == ClientState.ONLINE else "5. Reconnect")
        print("6. Exit")
        print("========================")

    def run(self):
        while self.running:
            self.display_menu()
            choice = input("Enter your choice (1-6): ")

            if choice == "1":
                self.handle_upload()
            elif choice == "2":
                self.handle_download()
            elif choice == "3":
                self.handle_list_files()
            elif choice == "4":
                self.handle_remove_file()
            elif choice == "5":
                self.handle_connection()
            elif choice == "6":
                self.handle_exit()
            else:
                print("Invalid choice. Please try again.")

    def handle_upload(self):
        if self.client.state == ClientState.OFFLINE:
            print("Client is offline. Please reconnect first.")
            return

        filename = input("Enter the filename to upload: ")
        if self.client.upload_file(filename):
            print("File uploaded successfully")
        else:
            print("Failed to upload file")

    def handle_download(self):
        if self.client.state == ClientState.OFFLINE:
            print("Client is offline. Please reconnect first.")
            return

        filename = input("Enter the filename to download: ")
        if self.client.download_file(filename):
            print("File downloaded successfully")
        else:
            print("Failed to download file")

    def handle_list_files(self):
        if self.client.state == ClientState.OFFLINE:
            print("Client is offline. Please reconnect first.")
            return

        files = self.client.list_files()
        if files:
            print("\nAvailable files:")
            for file in files:
                print(f"- {file}")
        else:
            print("No files available")

    def handle_remove_file(self):
        if self.client.state == ClientState.OFFLINE:
            print("Client is offline. Please reconnect first.")
            return

        filename = input("Enter the filename to remove: ")
        if self.client.remove_file(filename):
            print("File removed successfully")
        else:
            print("Failed to remove file")

    def handle_connection(self):
        if self.client.state == ClientState.ONLINE:
            self.client.disconnect()
            print("Disconnected from server")
        else:
            try:
                self.client.reconnect()
                print("Reconnected to server")
            except Exception as e:
                print(f"Failed to reconnect: {e}")

    def handle_exit(self):
        if self.client.state == ClientState.ONLINE:
            self.client.disconnect()
        self.running = False
        print("Goodbye!")
