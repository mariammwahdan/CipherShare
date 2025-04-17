class ServerError(Exception):
    """Base exception for server errors"""
    pass

class DatabaseError(ServerError):
    """Database related errors"""
    pass

class ProtocolError(ServerError):
    """Protocol handling errors"""
    pass

class ClientHandlingError(ServerError):
    """Client handling errors"""
    pass