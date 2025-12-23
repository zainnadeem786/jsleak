import unittest
from jsleak.scanner import Scanner, CONFIDENCE_HIGH, CONFIDENCE_LOW
from jsleak.reporter import Reporter
from jsleak.config import load_config
import os
import tempfile
import yaml

class TestV030(unittest.TestCase):
    def test_masking(self):
        rep = Reporter("text", redact_strategy="partial")
        secret = "AKIA1234567890123456"
        masked = rep.mask_secret(secret)
        self.assertEqual(masked, "AKIA************3456")
        
        short_secret = "123456"
        masked_short = rep.mask_secret(short_secret)
        self.assertEqual(masked_short, "******")

    def test_confidence_scoring(self):
        scanner = Scanner()
        # High entropy generic key needs to look like a key (length, chars)
        # Our regex for Generic API Key requires prefix: api_key=... or similar
        # "8973h4kjsdhy89723hjkahsd8973h4kjsdhy89723hjkahsd" alone won't match regex
        # We need context:
        high_ent = "8973h4kjsdhy89723hjkahsd8973h4kjsdhy89723hjkahsd"
        res = scanner.scan(f"const api_key = '{high_ent}';")
        match = next((m for m in res.matches if m.type == "Generic API Key"), None)
        self.assertIsNotNone(match)
        self.assertTrue(match.confidence in ["HIGH", "MEDIUM"])

    def test_config_loader(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yml") as f:
            yaml.dump({"confidence_threshold": "HIGH"}, f)
            fname = f.name
            
        cfg = load_config(fname)
        self.assertEqual(cfg.confidence_threshold, "HIGH")
        os.unlink(fname)

if __name__ == '__main__':
    unittest.main()
