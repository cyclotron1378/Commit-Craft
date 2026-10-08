"""Unit tests for pure Python diff parser."""

import unittest

from src.diff_parser import DiffParser


class TestDiffParser(unittest.TestCase):
    def test_empty_diff(self):
        parsed = DiffParser.parse("")
        self.assertEqual(parsed.total_files, 0)
        self.assertEqual(parsed.total_additions, 0)
        self.assertEqual(parsed.total_deletions, 0)

    def test_single_file_additions_deletions(self):
        diff_text = """diff --git a/app.py b/app.py
index e69de29..49b5d26 100644
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 import sys
-old_func()
+new_func()
+extra_line()
"""
        parsed = DiffParser.parse(diff_text)
        self.assertEqual(parsed.total_files, 1)
        self.assertEqual(parsed.total_additions, 2)
        self.assertEqual(parsed.total_deletions, 1)

        f = parsed.files[0]
        self.assertEqual(f.file_path, "app.py")
        self.assertEqual(len(f.hunks), 1)

        hunk = f.hunks[0]
        self.assertEqual(hunk.old_start, 1)
        self.assertEqual(hunk.new_start, 1)
        self.assertEqual(len(hunk.added_lines), 2)
        self.assertEqual(len(hunk.deleted_lines), 1)

    def test_multi_file_diff(self):
        diff_text = """diff --git a/file1.py b/file1.py
--- a/file1.py
+++ b/file1.py
@@ -1,1 +1,2 @@
 line1
+line2
diff --git a/file2.js b/file2.js
--- a/file2.js
+++ b/file2.js
@@ -1,2 +1,1 @@
-lineA
 lineB
"""
        parsed = DiffParser.parse(diff_text)
        self.assertEqual(parsed.total_files, 2)
        self.assertEqual(parsed.total_additions, 1)
        self.assertEqual(parsed.total_deletions, 1)
        self.assertIsNotNone(parsed.get_file("file1.py"))
        self.assertIsNotNone(parsed.get_file("file2.js"))

    def test_line_number_tracking(self):
        diff_text = """--- a/calc.py
+++ b/calc.py
@@ -10,3 +10,4 @@
 def add(a, b):
+    # new comment
     return a + b
"""
        parsed = DiffParser.parse(diff_text)
        hunk = parsed.files[0].hunks[0]
        add_line = hunk.added_lines[0]
        self.assertEqual(add_line.new_line_no, 11)
        self.assertEqual(add_line.content.strip(), "# new comment")


if __name__ == "__main__":
    unittest.main()
