"""Lets `python3 -m pytest tests` run the suites.

Each test_*.py here is a plain script (prints OK/FAIL lines, exits non-zero on a
failure) that sets its environment and database *before* importing app. Importing
them side by side in one pytest process would mix those setups, so every file is
run as its own subprocess and counts as one test.
"""
import subprocess
import sys

import pytest


def pytest_collect_file(parent, file_path):
    if file_path.suffix == ".py" and file_path.name.startswith("test_"):
        return ScriptFile.from_parent(parent, path=file_path)
    return None


class ScriptFile(pytest.File):
    def collect(self):
        yield ScriptItem.from_parent(self, name=self.path.stem)


class ScriptItem(pytest.Item):
    def runtest(self):
        proc = subprocess.run([sys.executable, str(self.path)], capture_output=True,
                              text=True, cwd=str(self.path.parent.parent), timeout=300)
        self.output = proc.stdout + proc.stderr
        if proc.returncode != 0:
            fails = [l for l in proc.stdout.splitlines() if l.startswith("FAIL")]
            raise AssertionError("\n".join(fails) or self.output[-3000:])

    def repr_failure(self, excinfo):
        return str(excinfo.value)

    def reportinfo(self):
        return self.path, 0, self.name
