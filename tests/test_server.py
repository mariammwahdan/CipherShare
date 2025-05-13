import unittest
from unittest.mock import MagicMock

from server import DatabaseManager, SessionManager, AuthManager
import tempfile
import os
import json
from pathlib import Path

class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager()
        self.db.files_db_path = Path(self.test_dir.name) / "files.json"
        self.db.users_db_path = Path(self.test_dir.name) / "users.json"
        self.db.sessions_db_path = Path(self.test_dir.name) / "sessions.json"

        for file in [self.db.files_db_path, self.db.users_db_path, self.db.sessions_db_path]:
            with open(file, "w") as f:
                json.dump([], f)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_add_and_get_user(self):
        user_info = {"username": "alice", "password_hash": "hash"}
        self.db.add_user(user_info)
        user = self.db.get_user("alice")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "alice")

    def test_add_and_remove_file(self):
        file_info = {
            "filename": "doc.txt", "owner": "alice", "ip": "127.0.0.1", "port": 5000, "online": True
        }
        self.db.add_file(file_info)
        removed = self.db.remove_file("alice", "doc.txt", ("127.0.0.1", 5000))
        self.assertTrue(removed)

    def test_add_and_clean_session(self):
        session_info = {"session_id": "xyz", "username": "bob", "expiry": 0}
        self.db.add_session(session_info)
        removed = self.db.clean_expired_sessions()
        self.assertEqual(removed, 1)

class TestAuthManager(unittest.TestCase):
    def test_hash_and_verify_password(self):
        db = MagicMock()
        auth = AuthManager(db)
        password = "Secret123"
        hash_val = auth.hash_password_argon(password)
        self.assertTrue(auth.verify_password(password, hash_val))


if __name__ == "__main__":
    unittest.main()
