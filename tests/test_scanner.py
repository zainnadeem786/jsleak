import unittest
from jsleak.scanner import scan_content, ScanResult

class TestScanner(unittest.TestCase):
    def test_secrets_detection(self):
        content = """
        var aws = "AKIAABCDEFGHIJKLMNOP";
        var google = "AIzaSyD-1234567890abcdef1234567890abcde";
        """
        result = scan_content(content)
        self.assertIn("AWS Access Key", result.secrets)
        self.assertIn("AKIAABCDEFGHIJKLMNOP", result.secrets["AWS Access Key"])
        self.assertIn("Google API Key", result.secrets)
    
    def test_endpoint_detection(self):
        content = """
        fetch("https://api.example.com/v1/data");
        const path = "/api/v2/user";
        """
        result = scan_content(content)
        self.assertIn("Absolute URL", result.endpoints)
        self.assertIn("https://api.example.com/v1/data", result.endpoints["Absolute URL"])
        self.assertIn("Relative API Path", result.endpoints)
        self.assertIn("/api/v2/user", result.endpoints["Relative API Path"])

    def test_no_false_positives(self):
        content = "var x = 10; var y = 'hello world';"
        result = scan_content(content)
        self.assertEqual(len(result.secrets), 0)
        self.assertEqual(len(result.endpoints), 0)

if __name__ == '__main__':
    unittest.main()
