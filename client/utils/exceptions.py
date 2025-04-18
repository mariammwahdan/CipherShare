class ClientError(Exception):
    """Base exception for client errors"""
    pass

class ConnectionError(ClientError):
    """Error when connecting to server"""
    pass

class FileTransferError(ClientError):
    """Error during file transfer"""
    pass

class ProtocolError(ClientError):
    """Error in protocol handling"""
    pass