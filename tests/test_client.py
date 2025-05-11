import unittest
from unittest.mock import patch, MagicMock, mock_open
from enum import Enum, auto

from client import FileSharingClient, ClientState


# Assuming FileSharingClient and ClientState are imported correctly

class TestFileSharingClient(unittest.TestCase):

    def setUp(self):
        self.client = FileSharingClient(server_host='localhost', server_port=5555)
        self.client.send_and_receive = MagicMock()

    def test_initial_state(self):
        self.assertEqual(self.client.state, ClientState.DISCONNECTED)
        self.assertIsNone(self.client.username)
        self.assertIsNone(self.client.session_id)

    @patch('os.path.isfile', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data=b'mydata')
    @patch('json.load', return_value={'username': 'alice', 'password': 'encrypted'})
    @patch.object(FileSharingClient, 'send_and_receive')
    def test_upload_file_success(self, mock_send, mock_json, mock_open_fn, mock_isfile):
        self.client.state = ClientState.AUTHENTICATED
        self.client.session_id = "abc123"
        mock_send.return_value = {'type': 'SUCCESS', 'data': {'message': 'ok'}}

        success, msg = self.client.upload_file("D:/SEMESTER 10/test1.txt")
        self.assertTrue(success)
        self.assertIn("now available", msg)

    def test_check_session_valid(self):
        self.client.session_id = 'valid-session'
        self.client.send_and_receive.return_value = {'type': 'SUCCESS', 'data': {}}
        self.assertTrue(self.client.check_session())

    def test_check_session_invalid(self):
        self.client.session_id = 'expired-session'
        self.client.state = ClientState.AUTHENTICATED
        self.client.send_and_receive.return_value = {'type': 'ERROR', 'data': {}}
        result = self.client.check_session()
        self.assertFalse(result)
        self.assertEqual(self.client.state, ClientState.CONNECTED)

    def test_list_files_success(self):
        self.client.state = ClientState.AUTHENTICATED
        self.client.session_id = 'abc123'
        self.client.send_and_receive.return_value = {
            'type': 'SUCCESS',
            'data': {'files': [{'filename': 'doc.txt', 'owner': 'bob'}]}
        }

        success, msg, files = self.client.list_files()
        self.assertTrue(success)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]['filename'], 'doc.txt')

    def test_list_files_failure(self):
        self.client.state = ClientState.AUTHENTICATED
        self.client.send_and_receive.return_value = {'type': 'ERROR', 'data': {'message': 'fail'}}
        success, msg, files = self.client.list_files()
        self.assertFalse(success)
        self.assertEqual(files, [])

    def test_remove_file_not_shared(self):
        self.client.state = ClientState.AUTHENTICATED
        result, msg = self.client.remove_file("nonexistent.txt")
        self.assertFalse(result)
        self.assertIn("not being shared", msg)

    def test_remove_file_success(self):
        self.client.state = ClientState.AUTHENTICATED
        self.client.shared_files = ["shared.txt"]
        self.client.send_and_receive.return_value = {'type': 'SUCCESS', 'data': {}}

        success, msg = self.client.remove_file("shared.txt")
        self.assertTrue(success)
        self.assertIn("removed successfully", msg)

    def test_disconnect(self):
        self.client.state = ClientState.AUTHENTICATED
        self.client.server_socket = MagicMock()
        self.client.session_id = 'abc123'
        self.client.send_and_receive.return_value = {'type': 'SUCCESS', 'data': {}}

        success, msg = self.client.disconnect()
        self.assertTrue(success)
        self.assertEqual(self.client.state, ClientState.DISCONNECTED)

    def test_disconnect_already(self):
        self.client.state = ClientState.DISCONNECTED
        success, msg = self.client.disconnect()
        self.assertTrue(success)
        self.assertIn("Already disconnected", msg)

if __name__ == '__main__':
    unittest.main()
