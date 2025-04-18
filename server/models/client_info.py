from dataclasses import dataclass
import socket
from typing import Set

@dataclass
class ClientInfo:
    host: str
    port: int
    socket: socket.socket
    is_online: bool = True
    shared_files: Set[str] = None

    def __post_init__(self):
        if self.shared_files is None:
            self.shared_files = set()

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"