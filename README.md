# CipherShare User Manual

## Introduction

CipherShare is a secure distributed file sharing platform with user-centric credential management. This manual provides step-by-step instructions for setting up and running the CipherShare application.

## Requirements

- Python 3.7 or higher
- No external dependencies required

## Installation

1. Clone or download the CipherShare files to your local machine
2. Make sure you have Python 3.7+ installed
3. No additional installation or setup is required

## File Structure

```
CipherShare/
│
├── main.py                # Main entry point
├── server.py              # Server implementation
├── client.py              # Client implementation
├── client_ui.py           # Client terminal UI
│
├── database/              # Directory for server database (created automatically)
├── shared_files/          # Directory for shared files (created automatically)
├── downloaded_files/      # Directory for downloaded files (created automatically)
```

## Running the Server

1. Open a terminal/command prompt
2. Navigate to the CipherShare directory
3. Run the server with the following command:

```
python main.py server [host] [port]
```

For example:
```
python main.py server 0.0.0.0 5555
```

This will start the server listening on all interfaces (0.0.0.0) on port 5555.

### Server Command Line Options

- `host`: The IP address the server should listen on (default: 0.0.0.0)
- `port`: The port number the server should listen on (default: 5555)

## Running the Client

1. Open a new terminal/command prompt (keep the server running)
2. Navigate to the CipherShare directory
3. Run the client with the following command:

```
python main.py client [server_host] [server_port]
```

For example:
```
python main.py client localhost 5555
```

This will start the client and attempt to connect to the server running on localhost:5555.

### Client Command Line Options

- `server_host`: The IP address of the server (default: localhost)
- `server_port`: The port number of the server (default: 5555)

## Using CipherShare

### First-time Setup

1. Start the server
2. Start the client
3. Register a new account

### Registration

1. From the main menu, select "Register new account"
2. Enter a username
3. Enter a password
4. You will be automatically logged in upon successful registration

### Login

1. From the main menu, select "Login"
2. Enter your username
3. Enter your password

### Sharing a File

1. Make sure you are logged in
2. From the main menu, select "Upload a file"
3. Enter the path to the file you want to share
4. The file will be copied to the shared_files directory and made available to other users

### Downloading a File

1. Make sure you are logged in
2. From the main menu, select "Download a file"
3. View the list of available files
4. Select the file you want to download by number
5. The file will be downloaded to the downloaded_files directory

### Viewing Available Files

1. From the main menu, select "List available files"
2. You'll see a list of all files available for download

### Managing Your Shared Files

1. From the main menu, select "List my shared files" to see what you're sharing
2. To stop sharing a file, select "Remove a shared file" and choose the file to remove

### Disconnecting

1. From the main menu, select "Disconnect" to go offline
2. Your files will no longer be available to other users

### Exiting

1. From any menu, select "0" or press Ctrl+C to exit
2. The application will gracefully disconnect from the server

## Running Multiple Clients

You can run multiple client instances to share files between different users:

1. Keep the server running
2. Open multiple terminals/command prompts
3. Run the client command in each terminal
4. Register different user accounts for each client
5. Share files from one client and download them on another

## Troubleshooting

### Connection Issues

- Make sure the server is running before starting clients
- Check that you're using the correct IP address and port
- Verify that no firewall is blocking the connections

### File Transfer Problems

- Ensure both clients are online (connected to the server)
- Check that the file exists in the shared_files directory of the sharing client
- Verify that both clients can connect to each other directly

### Login Issues

- Double-check your username and password
- Sessions expire after 5 minutes of inactivity, so you may need to login again

## Logs

The application creates log files that can help diagnose issues:

- `server_log.txt`: Contains server activities and errors
- `client_log.txt`: Contains client activities and errors

## Additional Information

- All passwords are securely hashed before storage (SHA-256)
- Files are stored in their original format without encryption in this phase
- User sessions automatically expire after 5 minutes of inactivity
- File transfers happen directly between clients (peer-to-peer)
