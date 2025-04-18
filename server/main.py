from core.server import Server
from utils.logger import logger
from utils.exceptions import ServerError
from config import DEFAULT_HOST, DEFAULT_PORT, DB_FILE

def main():
    server = None
    try:
        server = Server(DEFAULT_HOST, DEFAULT_PORT, DB_FILE)
        server.start()
    except ServerError as e:
        logger.error(f"Server error: {e}")
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        if server:
            server.stop()

if __name__ == "__main__":
    main()