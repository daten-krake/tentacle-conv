#!/usr/bin/env python3
"""
Synchronize ARM JSON files to YAML outputs with manifest-based state tracking.

Design:
- One JSON manifest per ARM source (e.g. arm/foo.json -> arm/foo.json.manifest)
- Idempotency via source ARM SHA-256 comparison. If the ARM file hash matches the
  recorded hash, conversion is skipped and YAML files are NOT touched.
- Atomic per-ARM: convert into a temp directory first; only copy to yaml/ after
  tentacle-conv succeeds.
- Orphaned YAML files (present in yaml/ but not referenced by any active manifest)
  are warned about but never deleted.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(os.environ.get("REPO_ROOT", os.getcwd()))
ARM_DIR = REPO_ROOT / "arm"
YAML_DIR = REPO_ROOT / "yaml"
TENTACLE_CONV = os.environ.get("TENTACLE_CONV", str(REPO_ROOT / "tentacle-conv"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def read_manifest(manifest_path: Path) -> dict | None:
    if not manifest_path.exists():
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def write_manifest(manifest_path: Path, data: dict) -> None:
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def find_arm_files() -> list[Path]:
    if not ARM_DIR.is_dir():
        return []
    files = sorted(
        p for p in ARM_DIR.rglob("*.json")
        if p.name != ".gitkeep"
        and not p.name.endswith(".manifest")
    )
    return files


def convert_arm_to_temp(arm_path: Path, tmpdir: Path) -> None:
    cmd = [
        TENTACLE_CONV,
        "-mode", "yaml",
        "-array",
        "-file", str(arm_path),
        "-outpath", str(tmpdir),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def sync() -> int:
    exit_code = 0
    YAML_DIR.mkdir(parents=True, exist_ok=True)

    arm_files = find_arm_files()
    if not arm_files:
        print("No ARM JSON files found in arm/.", file=sys.stderr)
        return 0

    # Build the set of all YAMLs currently referenced by any manifest.
    referenced_yamls: set[Path] = set()

    for arm_path in arm_files:
        manifest_path = arm_path.with_suffix(arm_path.suffix + ".manifest")
        current_arm_hash = sha256_file(arm_path)
        manifest = read_manifest(manifest_path)

        if manifest and manifest.get("source_sha256") == current_arm_hash:
            # ARM source unchanged since last run — idempotent skip.
            for entry in manifest.get("generated_yamls", []):
                yp = entry.get("yaml_path")
                if yp:
                    referenced_yamls.add(REPO_ROOT / yp)
            print(f"Skip (unchanged source): {arm_path}")
            continue

        # ARM source changed or no manifest yet — convert.
        with tempfile.TemporaryDirectory(prefix="tentacle_conv_") as tmpdir:
            tmpdir_path = Path(tmpdir)
            try:
                convert_arm_to_temp(arm_path, tmpdir_path)
            except subprocess.CalledProcessError as exc:
                print(
                    f"Error converting {arm_path}: {exc.stderr or exc.stdout or 'tentacle-conv failed'}",
                    file=sys.stderr,
                )
                exit_code = 1
                continue

            generated_yamls = sorted(tmpdir_path.glob("*.yaml"))
            if not generated_yamls:
                print(
                    f"Warning: no YAMLs generated from {arm_path}",
                    file=sys.stderr,
                )
                continue

            new_entries = []
            for gen_yaml in generated_yamls:
                target = YAML_DIR / gen_yaml.name
                gen_hash = sha256_file(gen_yaml)

                if target.exists():
                    existing_hash = sha256_file(target)
                    if existing_hash == gen_hash:
                        print(f"Unchanged: {target}")
                    else:
                        shutil.copy2(gen_yaml, target)
                        print(f"Updated: {target}")
                else:
                    shutil.copy2(gen_yaml, target)
                    print(f"Created: {target}")

                new_entries.append({
                    "yaml_path": str(target.relative_to(REPO_ROOT)),
                    "yaml_sha256": gen_hash,
                })
                referenced_yamls.add(target)

            manifest = {
                "source_arm_path": str(arm_path.relative_to(REPO_ROOT)),
                "source_sha256": current_arm_hash,
                "generated_yamls": new_entries,
                "last_converted_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            write_manifest(manifest_path, manifest)

    # Orphan detection: warn about YAMLs not referenced by any manifest.
    if YAML_DIR.is_dir():
        for yaml_path in sorted(YAML_DIR.rglob("*.yaml")):
            if yaml_path.name == ".gitkeep":
                continue
            if yaml_path not in referenced_yamls:
                print(
                    f"::warning::Orphaned YAML not referenced by any ARM manifest: {yaml_path}",
                    file=sys.stderr,
                )

    return exit_code


if __name__ == "__main__":
    sys.exit(sync())
