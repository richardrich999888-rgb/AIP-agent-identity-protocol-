"""A reviewed import deviation must not exempt future edits to that path."""
import contextlib
import importlib.util
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]


class ImportManifestTests(unittest.TestCase):
    def test_reviewed_tree_passes_but_extra_change_fails(self):
        source = ROOT / "orbitaltrust-accountability"
        spec = importlib.util.spec_from_file_location("manifest_check", source / "verify_manifest.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            target = Path(tmp) / "import"
            shutil.copytree(source, target)
            with patch.object(module, "HERE", target):
                self.assertEqual(module.main(), 0)
                registry = target / "rust/ot-sentinel/src/registry.rs"
                registry.write_text(registry.read_text() + "\n// unreviewed mutation\n")
                self.assertEqual(module.main(), 1)


if __name__ == "__main__":
    unittest.main()
