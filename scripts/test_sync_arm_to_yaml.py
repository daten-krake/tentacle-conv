#!/usr/bin/env python3
"""Tests for sync_arm_to_yaml.py. Builds the real converter, so it needs Go."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "sync_arm_to_yaml.py"


def arm_template(*names: str) -> str:
    rtype = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
    return json.dumps({
        "resources": [
            {
                "name": f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/ID-{n}')]",
                "type": rtype,
                "kind": "Scheduled",
                "properties": {
                    "displayName": n,
                    "severity": "High",
                    "query": "print 1",
                    "queryFrequency": "PT1H",
                    "queryPeriod": "PT1H",
                    "tactics": [],
                    "techniques": [],
                },
            }
            for n in names
        ]
    })


class SyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin_dir = tempfile.mkdtemp()
        cls.binary = os.path.join(cls.bin_dir, "tentacle-conv")
        subprocess.run(
            ["go", "build", "-o", cls.binary, "./cmd/tentacle-conv"],
            cwd=REPO, check=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.bin_dir, ignore_errors=True)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "arm").mkdir()
        (self.root / "internal").mkdir()
        (self.root / "internal" / "conv.go").write_text("package conversion // v1\n")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def put_arm(self, rel: str, *names: str):
        p = self.root / "arm" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(arm_template(*names))
        return p

    def run_sync(self, *args: str):
        env = dict(os.environ, REPO_ROOT=str(self.root), TENTACLE_CONV=self.binary)
        env.pop("SYNC_FORCE", None)
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            env=env, capture_output=True, text=True,
        )

    def manifest(self, rel="a.json"):
        return json.loads((self.root / "arm" / (rel + ".manifest")).read_text())

    def test_creates_yaml_and_skips_when_nothing_changed(self):
        self.put_arm("a.json", "Rule_A", "Rule_B")
        r = self.run_sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.root / "yaml" / "Rule_A.yaml").is_file())
        self.assertIn("converter_sha256", self.manifest())

        r = self.run_sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Skip (unchanged source and converter)", r.stdout)

    def test_converter_change_regenerates(self):
        self.put_arm("a.json", "Rule_A")
        self.assertEqual(self.run_sync().returncode, 0)
        before = self.manifest()["converter_sha256"]

        (self.root / "internal" / "conv.go").write_text("package conversion // v2\n")
        r = self.run_sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Skip", r.stdout)
        self.assertNotEqual(self.manifest()["converter_sha256"], before)

    def test_test_files_do_not_change_the_fingerprint(self):
        self.put_arm("a.json", "Rule_A")
        self.assertEqual(self.run_sync().returncode, 0)
        (self.root / "internal" / "conv_test.go").write_text("package conversion\n")
        r = self.run_sync()
        self.assertIn("Skip", r.stdout)

    def test_hand_edited_yaml_is_not_overwritten(self):
        self.put_arm("a.json", "Rule_A")
        self.assertEqual(self.run_sync().returncode, 0)
        target = self.root / "yaml" / "Rule_A.yaml"
        target.write_text(target.read_text() + "state: prod\n")

        (self.root / "internal" / "conv.go").write_text("package conversion // v2\n")
        r = self.run_sync()
        self.assertEqual(r.returncode, 1)
        self.assertIn("edited by hand", r.stderr)
        self.assertIn("state: prod", target.read_text())
        # The ARM file is looked at again on the next run.
        self.assertNotIn("converter_sha256", self.manifest())

        r = self.run_sync("--force")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("state: prod", target.read_text())
        self.assertIn("converter_sha256", self.manifest())

    def test_name_collision_across_files_writes_nothing(self):
        self.put_arm("a.json", "Same_Name")
        self.put_arm("nested/b.json", "Same_Name")
        r = self.run_sync()
        self.assertEqual(r.returncode, 1)
        self.assertIn("produced by several ARM files", r.stderr)
        self.assertFalse((self.root / "yaml" / "Same_Name.yaml").exists())

    def test_failed_conversion_keeps_previous_references(self):
        self.put_arm("a.json", "Rule_A")
        self.assertEqual(self.run_sync().returncode, 0)

        (self.root / "arm" / "a.json").write_text("{ not json")
        r = self.run_sync()
        self.assertEqual(r.returncode, 1)
        self.assertIn("Error converting", r.stderr)
        self.assertNotIn("Orphaned", r.stderr)
        self.assertTrue((self.root / "yaml" / "Rule_A.yaml").is_file())

    def test_unreferenced_yaml_is_reported_but_kept(self):
        self.put_arm("a.json", "Rule_A")
        (self.root / "yaml").mkdir()
        (self.root / "yaml" / "Old.yaml").write_text("name: Old\n")
        r = self.run_sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Orphaned YAML", r.stderr)
        self.assertTrue((self.root / "yaml" / "Old.yaml").is_file())


if __name__ == "__main__":
    unittest.main()
