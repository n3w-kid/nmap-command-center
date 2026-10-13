"""Run with: python -m unittest discover -s tests -v"""
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'worker'))
import main


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_root, self.previous_quarantine = main.ROOT, main.QUARANTINE
        main.ROOT = pathlib.Path(self.temp.name)
        main.QUARANTINE = main.ROOT / 'custom-quarantine'
        main.QUARANTINE.mkdir()
        self.client = TestClient(main.app)

    def tearDown(self):
        main.ROOT, main.QUARANTINE = self.previous_root, self.previous_quarantine
        self.temp.cleanup()

    def test_url_is_resolved_and_scoped(self):
        r = self.client.post('/preview', json={'target': 'http://127.0.0.1:8000/ignored', 'steps': [{'profile': 'quick'}]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()['resolvedTargets'], ['127.0.0.1'])
        self.assertEqual(self.client.post('/preview', json={'target': 'https://8.8.8.8/', 'steps': [{}]}).status_code, 403)

    def test_command_injection_and_unsafe_scripts_denied(self):
        for flags in ['-sT ; rm -rf /', '--script all', '--script exploit', '-oA /tmp/override',
                      '-sT 8.8.8.8', '--max-rate 10000']:
            with self.subTest(flags=flags):
                r = self.client.post('/preview', json={'target': '127.0.0.1', 'steps': [{'flags': flags}]})
                self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(self.client.post('/preview', json={'target': '127.0.0.1', 'steps': [{}, {}, {}, {}]}).status_code, 422)
        self.assertEqual(self.client.post('/preview', json={'target': '127.0.0.1'}).status_code, 422)
        self.assertEqual(self.client.post('/preview', json={'target': '127.0.0.1', 'steps': [{'timing': 5}]}).status_code, 422)

    def test_catalog_parses_and_restricts_categories(self):
        db = main.ROOT / 'script.db'
        db.write_text('Entry { filename = "http-title.nse", categories = { "safe", "discovery", } }\n'
                      'Entry { filename = "ssl-enum-ciphers.nse", categories = { "intrusive", "discovery", } }\n'
                      'Entry { filename = "unsafe-test.nse", categories = { "safe", "exploit", } }\n')
        with patch.object(main, 'SCRIPT_DB_LOCATIONS', [str(db)]):
            entries = {x['name']: x for x in main.catalog()}
            self.assertTrue(entries['http-title']['runnable'])
            self.assertFalse(entries['ssl-enum-ciphers']['runnable'])
            self.assertFalse(entries['unsafe-test']['runnable'])

    def test_private_lab_requires_admin_and_exact_allowlisted_target(self):
        db = main.ROOT / 'script.db'
        db.write_text('Entry { filename = "test-lab-risk.nse", categories = { "dos", "intrusive", } }\n'
                      'Entry { filename = "http-title.nse", categories = { "safe", } }\n'
                      'Entry { filename = "test-off-target.nse", categories = { "external", "safe", } }\n')
        secret = 'A-unique-admin-secret-for-testing'
        with patch.object(main, 'SCRIPT_DB_LOCATIONS', [str(db)]), \
             patch.object(main, 'ADMIN_TOKEN', secret), \
             patch.object(main, 'LAB_MODE_ENABLED', True), \
             patch.object(main, 'LAB_ALLOWED_IPS', {'127.0.0.1'}):
            entries = {x['name']:x for x in main.catalog()}
            self.assertFalse(entries['test-lab-risk']['runnable'])
            self.assertFalse(entries['test-off-target']['runnable'])
            r = self.client.post('/nse-approvals', json={'name':'test-lab-risk', 'note':'Reviewed in isolated training lab', 'lab_acknowledged': True})
            self.assertEqual(r.status_code, 403)
            r = self.client.post('/nse-approvals', headers={'X-Admin-Token':secret}, json={'name':'test-lab-risk', 'note':'Reviewed in isolated training lab', 'lab_acknowledged':True})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(next(x for x in main.catalog() if x['name'] == 'test-lab-risk')['runnable'])
            base = {'steps':[{'profile':'quick','scripts':['test-lab-risk']}], 'authorization_confirmed':True}
            r = self.client.post('/preview', json={**base, 'target':'127.0.0.1'})
            self.assertEqual(r.status_code, 200, r.text)
            for target in ['8.8.8.8', '127.0.0.0/30', '127.0.0.2']:
                r = self.client.post('/preview', json={**base, 'target':target})
                self.assertIn(r.status_code, (400,403), r.text)
            r = self.client.post('/scans', json={**base, 'target':'127.0.0.1', 'lab_mode':True, 'lab_confirmed':True})
            self.assertEqual(r.status_code, 403, r.text)
            r = self.client.post('/scans', headers={'X-Admin-Token':secret}, json={**base, 'target':'127.0.0.1', 'lab_mode':False, 'lab_confirmed':True})
            self.assertEqual(r.status_code, 403, r.text)
            r = self.client.post('/scans', headers={'X-Admin-Token':secret}, json={**base, 'target':'127.0.0.1', 'lab_mode':True, 'lab_confirmed':False})
            self.assertEqual(r.status_code, 403, r.text)

    def test_approved_disruptive_check_runs_only_with_lab_gate(self):
        db = main.ROOT / 'script.db'
        db.write_text('Entry { filename = "lab-fuzzer.nse", categories = { "fuzzer", "intrusive", } }\n')
        secret = 'unique-admin-token-for-test'
        launched = []
        class FakeProcess:
            def __init__(self, command, **kwargs):
                launched.append(command)
                self.pid = 123456
            def wait(self, timeout=None):
                return 0
            def poll(self):
                return 0
        with patch.object(main, 'SCRIPT_DB_LOCATIONS', [str(db)]), \
             patch.object(main, 'ADMIN_TOKEN', secret), \
             patch.object(main, 'LAB_MODE_ENABLED', True), \
             patch.object(main, 'LAB_ALLOWED_IPS', {'127.0.0.1'}), \
             patch.object(main.subprocess, 'Popen', FakeProcess):
            r = self.client.post('/nse-approvals', headers={'X-Admin-Token': secret},
                                 json={'name':'lab-fuzzer', 'note':'Isolated disposable lab system', 'lab_acknowledged':True})
            self.assertEqual(r.status_code, 200, r.text)
            request = {'target':'127.0.0.1', 'steps':[{'profile':'quick','scripts':['lab-fuzzer']}],
                       'authorization_confirmed':True, 'lab_mode':True, 'lab_confirmed':True}
            r = self.client.post('/scans', headers={'X-Admin-Token':secret}, json=request)
            self.assertEqual(r.status_code, 200, r.text)
            job_id = r.json()['id']
            for _ in range(100):
                state = self.client.get('/scans/' + job_id).json()
                if state['status'] == 'completed':
                    break
                time.sleep(0.005)
            self.assertEqual(state['status'], 'completed')
            self.assertEqual(len(launched), 1)
            self.assertIn('lab-fuzzer', ' '.join(map(str, launched[0])))
            self.assertIn('--script-timeout', launched[0])

    def test_custom_lua_quarantined(self):
        r = self.client.post('/custom-scripts', json={'filename': 'my-audit.lua', 'content': 'return {}'})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()['status'], 'quarantined')
        self.assertTrue((main.QUARANTINE / 'my-audit.lua').exists())
        self.assertEqual(self.client.post('/custom-scripts', json={'filename': '../oops.lua', 'content': 'x'}).status_code, 400)
        self.assertEqual(self.client.post('/custom-scripts', json={'filename': 'my-audit.lua', 'content': 'x'}).status_code, 409)

    def test_stop_after_failing_step(self):
        launches = []
        class FailingProcess:
            def __init__(self, argv, **kwargs):
                launches.append(argv)
                self.pid = 123456
            def wait(self, timeout=None):
                return 2
            def poll(self):
                return 2
        with patch.object(main.subprocess, 'Popen', FailingProcess):
            r = self.client.post('/scans', json={'target': '127.0.0.1', 'steps': [{}, {}, {}], 'authorization_confirmed': True})
            self.assertEqual(r.status_code, 200, r.text)
            identifier = r.json()['id']
            for _ in range(100):
                meta = self.client.get('/scans/' + identifier).json()
                if meta['status'] == 'failed':
                    break
                time.sleep(0.01)
            self.assertEqual(meta['status'], 'failed')
            self.assertEqual(len(launches), 1)
            self.assertEqual([s['status'] for s in meta['steps']], ['failed', 'queued', 'queued'])

    def test_three_steps_execute_in_order(self):
        launches = []
        class FakeProcess:
            def __init__(self, argv, **kwargs):
                launches.append(argv)
                self.pid = 123456
            def wait(self, timeout=None):
                time.sleep(0.035)
                return 0
            def poll(self):
                return None
        with patch.object(main.subprocess, 'Popen', FakeProcess):
            r = self.client.post('/scans', json={'target': '127.0.0.1', 'steps': [
                {'profile': 'quick'}, {'profile': 'services'}, {'profile': 'discovery'}], 'authorization_confirmed': True})
            self.assertEqual(r.status_code, 200, r.text)
            identifier = r.json()['id']
            for _ in range(100):
                latest = self.client.get('/scans/' + identifier).json()
                if latest['status'] not in ('queued', 'running'):
                    break
                time.sleep(0.015)
            self.assertEqual(latest['status'], 'completed', latest)
            self.assertEqual([x['status'] for x in latest['steps']], ['completed'] * 3)
            self.assertEqual(len(launches), 3)
            self.assertIn('scan-1', ' '.join(launches[0]))
            self.assertIn('scan-2', ' '.join(launches[1]))
            self.assertIn('scan-3', ' '.join(launches[2]))
            self.assertEqual(self.client.get('/scans/' + identifier + '/export/json?step=2').status_code, 200)


if __name__ == '__main__':
    unittest.main()
