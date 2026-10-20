import importlib.util
import pathlib
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('windows_fetch', pathlib.Path(__file__).parents[1] / 'windows/node/fetch-cid.py')
fetch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch)

class OperatorSources(unittest.TestCase):
    def test_file_overrides_manager_legacy_argument_and_is_reread(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = pathlib.Path(tmp) / 'sources.json'
            env = {'IPFS_GATEWAYS_FILE': str(file)}
            argv = ['fetch', 'cid', 'out', '100', 'https://retired.invalid']
            file.write_text('["http://127.0.0.1:8189"]')
            self.assertEqual(fetch.configured_gateway(argv, env), ['http://127.0.0.1:8189'])
            file.write_text('["http://127.0.0.1:8190"]')
            self.assertEqual(fetch.configured_gateway(argv, env), ['http://127.0.0.1:8190'])
    def test_invalid_explicit_file_never_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = pathlib.Path(tmp) / 'sources.json'
            env = {'IPFS_GATEWAYS_FILE': str(file)}
            argv = ['fetch', 'cid', 'out', '100', 'https://retired.invalid']
            for body in ('{', '[]', '"https://retired.invalid"', '["https://user:secret@example.com"]'):
                file.write_text(body)
                with self.assertRaises(ValueError): fetch.configured_gateway(argv, env)
            file.unlink()
            with self.assertRaises(FileNotFoundError): fetch.configured_gateway(argv, env)

if __name__ == '__main__': unittest.main()
