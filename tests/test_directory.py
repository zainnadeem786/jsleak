import unittest
import os
import tempfile
import shutil
from jsleak.ignorer import Ignorer
from jsleak.directory import scan_directory

class TestDirectoryScan(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.js_file = os.path.join(self.test_dir, "test.js")
        with open(self.js_file, "w") as f:
            f.write("var aws = 'AKIAABCDEFGHIJKLMNOP';")
            
        self.min_file = os.path.join(self.test_dir, "test.min.js")
        with open(self.min_file, "w") as f:
            f.write("var aws = 'AKIAABCDEFGHIJKLMNOP';")
            
        self.txt_file = os.path.join(self.test_dir, "test.txt")
        with open(self.txt_file, "w") as f:
            f.write("nothing")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_scan_directory(self):
        results = list(scan_directory(self.test_dir))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["file"], self.js_file)
        self.assertIn("AWS Access Key", results[0]["secrets"])

    def test_ignore_rules(self):
        ignore_file = os.path.join(self.test_dir, ".jsleakignore")
        with open(ignore_file, "w") as f:
            f.write("test.js\n")
            
        ignorer = Ignorer(ignore_file)
        results = list(scan_directory(self.test_dir, ignorer=ignorer))
        self.assertEqual(len(results), 0)

    def test_ignore_secret_type(self):
        ignore_file = os.path.join(self.test_dir, ".jsleakignore")
        with open(ignore_file, "w") as f:
            f.write("AWS Access Key\n")
            
        ignorer = Ignorer(ignore_file)
        results = list(scan_directory(self.test_dir, ignorer=ignorer))
        self.assertEqual(len(results), 1)
        # Should be empty because we ignored the only secret type found
        self.assertEqual(len(results[0]["secrets"]), 0)

if __name__ == '__main__':
    unittest.main()
