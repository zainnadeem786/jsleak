import unittest
from jsleak.scanner import Scanner, Location, SecretMatch
from jsleak.reporter import Reporter
import tempfile
import os

class TestEnterprise(unittest.TestCase):
    def test_location_tracking(self):
        scanner = Scanner()
        content = """var x = 1;
// Some comments
var aws_key = "AKIA1234567890123456";
"""
        res = scanner.scan(content)
        match = res.matches[0]
        self.assertEqual(match.type, "AWS Access Key")
        self.assertEqual(match.location.line, 3)
        # "var aws_key = " is 14 chars. +1 quote = 15. Column should be around 16.
        # Let's count precisely:
        # line 1: var x = 1;\n (11 chars)
        # line 2: // Some comments\n (17 chars)
        # line 3: var aws_key = "AKIA...
        # 0123456789012345
        # var aws_key = "
        # 16th char is 'A'. So col 16 (1-indexed) or 15?
        # get_location logic: start_index - last_newline.
        # "A" is at index for AKIA. last_newline is end of line 2.
        # difference is match col. 
        self.assertEqual(match.location.column, 16) 

    def test_minified_location(self):
        scanner = Scanner()
        # Minified: one line
        content = 'var a=1;var k="AKIA1234567890123456";'
        res = scanner.scan(content)
        match = res.matches[0]
        self.assertEqual(match.location.line, 1)
        self.assertTrue(match.location.column > 10)

if __name__ == '__main__':
    unittest.main()
