from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from sentinel import main, scan_source


class RuleTests(unittest.TestCase):
    def test_reports_each_documented_rule(self) -> None:
        source = """\
import os

api_token = "demo-value"
query = f"SELECT * FROM users WHERE id = {user_id}"
os.system(command)
"""

        findings = scan_source(source)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["SEN003", "SEN002", "SEN001"],
        )

    def test_secret_value_is_never_stored_or_printed(self) -> None:
        secret = "sentinel-canary-7f8c1f8f2e6d"
        source = f'api_token = "{secret}"\n'
        findings = scan_source(source)

        self.assertEqual(len(findings), 1)
        self.assertNotIn(secret, repr(findings))

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.py"
            target.write_text(source, encoding="utf-8")
            before = target.read_bytes()
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main([str(target)])

            output = stdout.getvalue() + stderr.getvalue()
            self.assertEqual(exit_code, 1)
            self.assertNotIn(secret, output)
            self.assertIn("assignment to 'api_token'", output)
            self.assertIn("line 1", output)
            self.assertEqual(target.read_bytes(), before)

    def test_avoids_substring_and_non_string_false_positives(self) -> None:
        source = """\
monkey = "curious"
keyboard = "mechanical"
secretary = "person"
tokenizer = "parser"
password_length = 16
"""

        self.assertEqual(scan_source(source), [])

    def test_environment_lookup_is_not_a_literal_secret(self) -> None:
        source = """\
import os

api_key = os.getenv("API_KEY")
access_token = os.environ.get("ACCESS_TOKEN")
"""

        self.assertEqual(scan_source(source), [])

    def test_camel_case_and_annotated_secret_names_are_reported(self) -> None:
        source = """\
apiKey = "demo-one"
APIKey: str = "demo-two"
"""

        findings = scan_source(source)

        self.assertEqual([finding.rule_id for finding in findings], ["SEN003", "SEN003"])
        self.assertEqual(
            [finding.context for finding in findings],
            ["assignment to 'apiKey'", "assignment to 'APIKey'"],
        )

    def test_empty_secret_literal_is_not_reported(self) -> None:
        self.assertEqual(scan_source('password = ""\n'), [])

    def test_non_sql_f_string_is_not_reported(self) -> None:
        self.assertEqual(scan_source('message = f"Hello, {name}"\n'), [])

    def test_sql_keyword_is_not_joined_across_formatted_values(self) -> None:
        self.assertEqual(scan_source('message = f"SELE{middle}CT"\n'), [])

    def test_only_direct_os_system_calls_are_reported(self) -> None:
        source = """\
from os import system

system(command)
runner.system(command)
"""

        self.assertEqual(scan_source(source), [])


class CliTests(unittest.TestCase):
    def run_cli(self, path: Path) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main([os.fspath(path)])
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_clean_file_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "clean.py"
            target.write_text("answer = 42\n", encoding="utf-8")

            exit_code, stdout, stderr = self.run_cli(target)

        self.assertEqual(exit_code, 0)
        self.assertIn("No findings", stdout)
        self.assertEqual(stderr, "")

    def test_latin_1_source_with_encoding_cookie_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "latin1.py"
            target.write_bytes(b"# -*- coding: latin-1 -*-\nlabel = 'caf\xe9'\n")

            exit_code, stdout, stderr = self.run_cli(target)

        self.assertEqual(exit_code, 0)
        self.assertIn("No findings", stdout)
        self.assertEqual(stderr, "")

    def test_unknown_encoding_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "bad_encoding.py"
            target.write_bytes(b"# coding: definitely-not-a-codec\nvalue = 1\n")

            exit_code, stdout, stderr = self.run_cli(target)

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("could not decode or read", stderr)

    def test_invalid_utf_8_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "bad_utf8.py"
            target.write_bytes(b"# coding: utf-8\nlabel = '\xff'\n")

            exit_code, stdout, stderr = self.run_cli(target)

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("could not decode or read", stderr)

    def test_syntax_error_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "broken.py"
            target.write_text("def broken(:\n    pass\n", encoding="utf-8")

            exit_code, stdout, stderr = self.run_cli(target)

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("could not parse", stderr)

    def test_missing_file_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "missing.py"

            exit_code, stdout, stderr = self.run_cli(target)

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("could not decode or read", stderr)


if __name__ == "__main__":
    unittest.main()
