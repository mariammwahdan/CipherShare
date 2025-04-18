import socket
import threading
import json
import enum
import logging
from typing import Dict, List, Set, Optional
import time
from dataclasses import dataclass
import os


class DatabaseManager:
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.lock = threading.Lock()
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        if not os.path.exists(self.db_file):
            with open(self.db_file, 'w') as f:
                json.dump({"files": {}}, f)

    def load_data(self) -> dict:
        with self.lock:
            with open(self.db_file, 'r') as f:
                return json.load(f)

    def save_data(self, data: dict):
        with self.lock:
            with open(self.db_file, 'w') as f:
                json.dump(data, f, indent=4)

    def add_file(self, filename: str, client_host: str, client_port: int):
        data = self.load_data()
        if filename not in data["files"]:
            data["files"][filename] = []
        
        client_info = {"host": client_host, "port": client_port}
        if client_info not in data["files"][filename]:
            data["files"][filename].append(client_info)
            self.save_data(data)
            logging.info(f"Added file {filename} for client {client_host}:{client_port}")

    def remove_file(self, filename: str, client_host: str, client_port: int) -> bool:
        data = self.load_data()
        if filename in data["files"]:
            data["files"][filename] = [
                client for client in data["files"][filename]
                if not (client["host"] == client_host and client["port"] == client_port)
            ]
            if not data["files"][filename]:
                del data["files"][filename]
            self.save_data(data)
            logging.info(f"Removed file {filename} for client {client_host}:{client_port}")
            return True
        return False

    def get_file_locations(self, filename: str) -> List[dict]:
        data = self.load_data()
        return data["files"].get(filename, [])

    def get_all_files(self) -> List[str]:
        data = self.load_data()
        return list(data["files"].keys())

    def remove_client_files(self, client_host: str, client_port: int):
        data = self.load_data()
        for filename in list(data["files"].keys()):
            data["files"][filename] = [
                client for client in data["files"][filename]
                if not (client["host"] == client_host and client["port"] == client_port)
            ]
            if not data["files"][filename]:
                del data["files"][filename]
        self.save_data(data)
        logging.info(f"Removed all files for client {client_host}:{client_port}")