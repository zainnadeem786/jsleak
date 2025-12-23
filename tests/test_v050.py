import unittest
import json
import os
import tempfile
from unittest.mock import MagicMock, patch
from jsleak.reporter import Reporter
from jsleak.baseline_manager import BaselineManager
from jsleak.config import Config

class TestV050(unittest.TestCase):
    
    def test_baseline_manager(self):
        # Create a temp baseline file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            json.dump(["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"], f) # Dummy hash
            baseline_path = f.name
        
        try:
            mgr = BaselineManager(baseline_path)
            # Hash logic: file:type:value
            # We need to simulate the hash generation to verify suppression
            
            # Let's generate a signature first
            match = {"type": "AWS Access Key", "value": "AKIA123"}
            file = "test.js"
            sig = mgr.generate_signature(match, file)
            
            # Now update baseline with this sig
            with open(baseline_path, 'w') as f:
                json.dump([sig], f)
            
            # Reload
            mgr = BaselineManager(baseline_path)
            self.assertTrue(mgr.should_ignore(match, file))
            self.assertFalse(mgr.should_ignore(match, "other.js"))
            
        finally:
            os.unlink(baseline_path)

    def test_reporter_redaction(self):
        # Partial
        rep = Reporter("text", redact_strategy="partial")
        self.assertEqual(rep.mask_secret("AKIA1234567890"), "AKIA******7890")
        
        # Full
        rep = Reporter("text", redact_strategy="full")
        self.assertEqual(rep.mask_secret("AKIA1234567890"), "*" * 16)
        
        # None
        rep = Reporter("text", redact_strategy="none")
        self.assertEqual(rep.mask_secret("AKIA1234567890"), "AKIA1234567890")

    def test_stats_output(self):
        # Mock print
        with patch('builtins.print') as mock_print:
            rep = Reporter("stats")
            stats = {
                "files_scanned": 10,
                "secrets_found": 5,
                "endpoints_found": 20,
                "execution_time_seconds": 1.5
            }
            rep._print_stats(stats)
            # Verify json call
            args, _ = mock_print.call_args
            output = json.loads(args[0])
            self.assertEqual(output["files_scanned"], 10)
            self.assertEqual(output["secrets_found"], 5)

if __name__ == '__main__':
    unittest.main()
