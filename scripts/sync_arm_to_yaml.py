#!/usr/bin/env python3
"""
Synchronize ARM JSON files to YAML outputs with manifest-based state tracking.

Design:
- One JSON manifest per ARM source (e.g. arm/foo.json -> arm/foo.json.manifest)
- Idempotency: conversion is skipped when both the ARM file's SHA-256 and the
  converter's fingerprint (a hash of the Go sources the binary is built from)
  match the manifest. A converter change therefore regenerates existing YAML.
- Two phases: every ARM file is converted into a temp directory first and the
  results are checked as a whole; only then is anything copied to yaml/.
- Output names must be unique across all ARM files (yaml/ is flat). A name
  produced by two ARM files is an error and neither file is written.
- A YAML file whose content no longer matches the hash recorded in the manifest
  was edited by hand and is NOT overwritten; the script reports it and exits
  non-zero. Pass --force (or SYNC_FORCE=1) to overwrite such files.
- Orphaned YAML files (present in yaml/ but not referenced by any active manifest)
  are warned about but never deleted.
"""

import argparse
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

# Inputs that determine what the converter produces.
CONVERTER_SOURCE_GLOBS = ("cmd/**/*.go", "internal/**/*.go")
CONVERTER_SOURCE_FILES = ("go.mod", "go.sum")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def converter_fingerprint() -> str:
    """Hash of the converter's Go sources (tests excluded), or of the binary
    when the sources are not available."""
    files: list[Path] = []
    for pattern in CONVERTER_SOURCE_GLOBS:
        files.extend(
            p for p in REPO_ROOT.glob(pattern) if not p.name.endswith("_test.go")
        )
    files.extend(REPO_ROOT / n for n in CONVERTER_SOURCE_FILES if (REPO_ROOT / n).is_file())

    if not files:
        binary = Path(TENTACLE_CONV)
        return "binary:" + sha256_file(binary) if binary.is_file() else "unknown"

    h = hashlib.sha256()
    for p in sorted(set(files)):
        h.update(p.relative_to(REPO_ROOT).as_posix().encode())
        h.update(b"\0")
        h.update(sha256_file(p).encode())
        h.update(b"\0")
    return "src:" + h.hexdigest()


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
        "arm-to-yaml",
        "-array",
        "-file", str(arm_path),
        "-outpath", str(tmpdir),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def manifest_yaml_hashes(manifest: dict | None) -> dict[str, str]:
    """yaml_path -> yaml_sha256 recorded by the previous run."""
    if not manifest:
        return {}
    return {
        e["yaml_path"]: e.get("yaml_sha256", "")
        for e in manifest.get("generated_yamls", [])
        if e.get("yaml_path")
    }


def sync(force: bool = False) -> int:
    exit_code = 0

    if not Path(TENTACLE_CONV).is_file():
        print(f"Error: converter binary not found at {TENTACLE_CONV}", file=sys.stderr)
        return 1

    YAML_DIR.mkdir(parents=True, exist_ok=True)

    arm_files = find_arm_files()
    if not arm_files:
        print("No ARM JSON files found in arm/.", file=sys.stderr)
        return 0

    fingerprint = converter_fingerprint()

    # YAML paths kept by some manifest (never reported as orphans).
    referenced_yamls: set[Path] = set()
    # Output name -> ARM files that produce it, for collision detection.
    producers: dict[str, list[Path]] = {}
    # ARM files to (re)write, with their generated YAMLs.
    pending: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="tentacle_conv_") as tmp_root:
        # Phase 1: decide what to do for each ARM file and convert into temp.
        for i, arm_path in enumerate(arm_files):
            manifest_path = arm_path.with_suffix(arm_path.suffix + ".manifest")
            current_arm_hash = sha256_file(arm_path)
            manifest = read_manifest(manifest_path)
            previous = manifest_yaml_hashes(manifest)

            def keep_previous() -> None:
                for yp in previous:
                    referenced_yamls.add(REPO_ROOT / yp)
                    producers.setdefault(Path(yp).name, []).append(arm_path)

            if (
                manifest
                and manifest.get("source_sha256") == current_arm_hash
                and manifest.get("converter_sha256") == fingerprint
            ):
                keep_previous()
                print(f"Skip (unchanged source and converter): {arm_path}")
                continue

            tmpdir_path = Path(tmp_root) / str(i)
            tmpdir_path.mkdir()
            try:
                convert_arm_to_temp(arm_path, tmpdir_path)
            except subprocess.CalledProcessError as exc:
                print(
                    f"Error converting {arm_path}: {exc.stderr or exc.stdout or 'tentacle-conv failed'}",
                    file=sys.stderr,
                )
                exit_code = 1
                keep_previous()
                continue

            generated = sorted(tmpdir_path.glob("*.yaml"))
            if not generated:
                print(f"Warning: no YAMLs generated from {arm_path}", file=sys.stderr)
                keep_previous()
                continue

            for gen_yaml in generated:
                producers.setdefault(gen_yaml.name, []).append(arm_path)
            pending.append({
                "arm_path": arm_path,
                "manifest_path": manifest_path,
                "arm_hash": current_arm_hash,
                "previous": previous,
                "generated": generated,
            })

        # Name collisions across ARM files: write nothing for any involved file.
        conflicted: set[Path] = set()
        for name, owners in sorted(producers.items()):
            unique = sorted(set(owners))
            if len(unique) > 1:
                print(
                    f"Error: {YAML_DIR / name} is produced by several ARM files: "
                    + ", ".join(str(p) for p in unique),
                    file=sys.stderr,
                )
                conflicted.update(unique)
                exit_code = 1

        # Phase 2: write.
        for item in pending:
            arm_path = item["arm_path"]
            previous: dict[str, str] = item["previous"]

            if arm_path in conflicted:
                print(f"Not writing output of {arm_path}: name collision", file=sys.stderr)
                for yp in previous:
                    referenced_yamls.add(REPO_ROOT / yp)
                continue

            entries = []
            blocked = 0
            for gen_yaml in item["generated"]:
                target = YAML_DIR / gen_yaml.name
                rel = str(target.relative_to(REPO_ROOT))
                gen_hash = sha256_file(gen_yaml)
                referenced_yamls.add(target)

                if target.exists():
                    existing_hash = sha256_file(target)
                    if existing_hash == gen_hash:
                        print(f"Unchanged: {target}")
                        entries.append({"yaml_path": rel, "yaml_sha256": gen_hash})
                        continue
                    if not force and existing_hash != previous.get(rel):
                        print(
                            f"::warning::{target} differs from the last generated version "
                            "(edited by hand?); not overwriting. Use --force to overwrite.",
                            file=sys.stderr,
                        )
                        blocked += 1
                        exit_code = 1
                        entries.append({"yaml_path": rel, "yaml_sha256": previous.get(rel, existing_hash)})
                        continue
                    shutil.copy2(gen_yaml, target)
                    print(f"Updated: {target}")
                else:
                    shutil.copy2(gen_yaml, target)
                    print(f"Created: {target}")

                entries.append({"yaml_path": rel, "yaml_sha256": gen_hash})

            manifest = {
                "source_arm_path": str(arm_path.relative_to(REPO_ROOT)),
                "source_sha256": item["arm_hash"],
                "generated_yamls": entries,
                "last_converted_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            # Leave the converter hash out while files are blocked so the next
            # run looks at this ARM file again instead of skipping it.
            if not blocked:
                manifest["converter_sha256"] = fingerprint
            write_manifest(item["manifest_path"], manifest)

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--force",
        action="store_true",
        default=os.environ.get("SYNC_FORCE") == "1",
        help="overwrite YAML files that were modified since they were generated",
    )
    return sync(force=parser.parse_args().force)


if __name__ == "__main__":
    sys.exit(main())
