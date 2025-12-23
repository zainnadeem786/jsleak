import unittest
import json
from unittest.mock import MagicMock
# from jsleak.cli import _print_json # Removed, need to test Reporter instead or adapt test
from jsleak.reporter import Reporter
from jsleak.pattern_utils import get_severity as _get_severity
from jsleak.patterns import SEVERITY_HIGH, SEVERITY_MEDIUM
from jsleak.scanner import ScanResult

class TestCLI(unittest.TestCase):
    def test_get_severity(self):
        self.assertEqual(_get_severity("AWS Access Key"), SEVERITY_HIGH)
        self.assertEqual(_get_severity("Generic API Key"), SEVERITY_MEDIUM)
        
    def test_json_output_structure(self):
        # Mock scan result
        result = ScanResult(
            secrets={"AWS Access Key": ["AKIA123"]},
            endpoints={"Absolute URL": ["https://example.com"]},
            matches=[{"type": "AWS Access Key", "value": "AKIA123", "severity": "HIGH", "confidence": "HIGH", "line": 1, "column": 1}],
            endpoint_matches=[]
        )
        
        # Capture stdout
        from io import StringIO
        import sys
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Reporter instance
        rep = Reporter("json")
        result_dict = {
            "file": "test_file.js",
            "matches": [{"type": "AWS Access Key", "value": "AKIA123", "severity": "HIGH", "confidence": "HIGH", "line": 1, "column": 1}],
            "endpoints": result.endpoints,
            "error": None
        }
        
        rep.report([result_dict], {})
        
        sys.stdout = sys.__stdout__
        
        output = json.loads(captured_output.getvalue())
        
        # output is now a list of results
        self.assertEqual(output[0]["file"], "test_file.js")
        self.assertIn("AWS Access Key", output[0]["secrets"])
        self.assertEqual(output[0]["secrets"]["AWS Access Key"][0]["value"], "*******")
        self.assertEqual(output[0]["secrets"]["AWS Access Key"][0]["severity"], SEVERITY_HIGH)
        
    # Removed obsolete entropy test since method signature changed and logic is tested via confidence in v030
    pass

if __name__ == '__main__':
    unittest.main()
