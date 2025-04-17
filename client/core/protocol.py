import json
from utils.enums import MessageType

class Protocol:
    @staticmethod
    def create_message(msg_type: MessageType, data: dict) -> bytes:
        message = {
            "type": msg_type.value,
            "data": data
        }
        return json.dumps(message).encode()

    @staticmethod
    def parse_message(message: bytes) -> tuple:
        decoded = json.loads(message.decode())
        return MessageType(decoded["type"]), decoded["data"]