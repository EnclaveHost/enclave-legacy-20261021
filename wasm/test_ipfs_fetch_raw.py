"""Raw CID responses must meet the same content verification as CAR blocks."""
import base64
import hashlib
import io
import unittest
from unittest.mock import patch
import ipfs_fetch

class RawFetchTests(unittest.TestCase):
    def test_raw_content_is_verified_and_bounded(self):
        data = b'public fixture'
        cid = 'b' + base64.b32encode(b'\x01\x55\x12\x20' + hashlib.sha256(data).digest()).decode().lower().rstrip('=')
        for response, cap, valid in [(data, len(data), True),
                                     (b'wrong bytes', len(data), False),
                                     (data, len(data)-1, False)]:
            with self.subTest(response=response, cap=cap):
                with patch.object(ipfs_fetch.urllib.request, 'urlopen', return_value=io.BytesIO(response)):
                    if valid:
                        self.assertEqual(ipfs_fetch.fetch_verified(cid, 'https://example.test', cap), data)
                    else:
                        with self.assertRaises(ValueError):
                            ipfs_fetch.fetch_verified(cid, 'https://example.test', cap)

    def test_multiple_gateways_verify_each_attempt_and_never_append_legacy(self):
        data = b'bootstrap fixture'
        cid = 'b' + base64.b32encode(b'\x01\x55\x12\x20' + hashlib.sha256(data).digest()).decode().lower().rstrip('=')
        urls = []
        def reply(req, **kwargs):
            urls.append(req.full_url)
            return io.BytesIO(b'tampered' if 'first.test' in req.full_url else data)
        with patch.object(ipfs_fetch.urllib.request, 'urlopen', side_effect=reply):
            self.assertEqual(ipfs_fetch.fetch_verified(cid, '["https://first.test","https://second.test"]', 1024), data)
        self.assertEqual(len(urls), 2)
        self.assertTrue(all('enclave.host' not in u for u in urls))
        with patch.object(ipfs_fetch.urllib.request, 'urlopen', side_effect=OSError('offline')):
            with self.assertRaisesRegex(ValueError, 'no artifact gateway'):
                ipfs_fetch.fetch_verified(cid, ['https://first.test','https://second.test'], 1024)

    def test_invalid_gateway_lists_refuse(self):
        for value in ['[]', '["https://same.test","https://same.test"]', '["file:///etc/passwd"]', '["https://user:pass@host.test"]']:
            with self.assertRaises(ValueError):
                ipfs_fetch.gateway_config(value)

if __name__ == '__main__':
    unittest.main()
