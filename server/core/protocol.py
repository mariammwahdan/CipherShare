import json
from utils.enums import MessageType
from utils.exceptions import ProtocolError

class Protocol:
    @staticmethod
    def create_message(msg_type: MessageType, data: dict) -> bytes:
        try:
            message = {
                "type": msg_type.value,
                "data": data
            }
            return json.dumps(message).encode()
        except Exception as e:
            raise ProtocolError(f"Error creating message: {e}")

    @staticmethod
    def parse_message(message: bytes) -> tuple:
        try:
            decoded = json.loads(message.decode())
            return MessageType(decoded["type"]), decoded["data"]
        except Exception as e:
            raise ProtocolError(f"Error parsing message: {e}")