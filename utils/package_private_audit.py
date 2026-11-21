#!/usr/bin/env python3
"""Create an unpublished source handoff for the main developer, without wallet data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
        capture_output=True, text=True).stdout.strip()


def main():
    core = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui-repo", type=Path, default=core.parent / "salvium-gui")
    parser.add_argument("--output-dir", type=Path, required=True, help="New owner-only handoff directory")
    args = parser.parse_args()
    os.umask(0o077)
    destination = args.output_dir.resolve()
    archive = destination.with_name(destination.name + ".tar.gz")
    if destination.exists() or archive.exists():
        raise ValueError("Choose a new handoff path; existing files are never overwritten")
    gui = args.gui_repo.resolve()
    metadata = {}
    for name, repo, base in (("core", core, "main"), ("gui", gui, "master")):
        if git(repo, "branch", "--show-current") != "audit":
            raise ValueError(f"{name} must be on its audit branch")
        git(repo, "diff", "--quiet", "--ignore-submodules=untracked")
        git(repo, "diff", "--cached", "--quiet", "--ignore-submodules=untracked")
        git(repo, "merge-base", "--is-ancestor", base, "audit")
        metadata[name] = {"commit": git(repo, "rev-parse", "audit"),
            "base": git(repo, "rev-parse", base), "base_branch": base, "branch": "audit"}
    validation = core / "docs/AUDIT_PRIVATE_REVIEW_VALIDATION.json"
    if not validation.is_file():
        raise ValueError("Record current validation before preparing the private handoff")
    destination.mkdir(mode=0o700, parents=True)
    for name, repo in (("core", core), ("gui", gui)):
        bundle = destination / (name + ".bundle")
        git(repo, "bundle", "create", str(bundle), "audit", "^" + metadata[name]["base"])
        git(repo, "bundle", "verify", str(bundle))
    shutil.copy2(core / "docs/AUDIT_PRIVATE_HANDOFF.md", destination / "HANDOFF.md")
    shutil.copy2(validation, destination / "VALIDATION.json")
    (destination / "README.txt").write_text(
        "PRIVATE MAIN DEVELOPER HANDOFF — DO NOT UPLOAD PUBLICLY\n\n"
        "Read HANDOFF.md and VALIDATION.json first. No private signing key, owner\n"
        "evidence, exchange ledger, owner wallet, chain database or build binary is included.\n"
        "The designated main developer must generate/retain the signing secret and\n"
        "configure only its public key before releasing official wallets.\n\n"
        "Use existing core and GUI clones containing the base commits in source.json.\n"
        "Verify each bundle with: git bundle verify /private/path/core.bundle\n"
        "Fetch into the corresponding clone: git fetch /private/path/core.bundle audit\n"
        "Review FETCH_HEAD, then create/update only that repository's audit branch.\n"
        "Repeat with gui.bundle in the GUI clone. Preserve master/main.\n"
        "The GUI's salvium submodule pins a core commit included in core.bundle;\n"
        "fetch that bundle into the submodule too if the commit is not available.\n"
        "Build and test from source using the documented commands.\n")
    (destination / "source.json").write_text(json.dumps({"version": 1, "delivery": "PRIVATE",
        "repositories": metadata, "contains_owner_wallet_data": False, "contains_signing_secret": False,
        "files_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(destination.iterdir()) if p.is_file()}}, indent=2) + "\n")
    for path in destination.iterdir():
        path.chmod(0o600)
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        with tarfile.open(fileobj=stream, mode="w:gz") as packaged:
            packaged.add(destination, arcname=destination.name)
    checksum = archive.with_name(archive.name + ".sha256")
    with checksum.open("x") as out:
        out.write(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
    print(archive)


if __name__ == "__main__":
    main()
