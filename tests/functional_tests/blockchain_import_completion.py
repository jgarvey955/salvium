#!/usr/bin/env python3
"""Verify importer completion and exit status against a read-only chain export.

No daemon is launched. The source is opened by the read-only exporter; every
import writes to a new test directory under --output-dir.
"""
import argparse
import json
import os
import struct
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--source-data-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    binary = args.bin_dir.resolve()
    source = args.source_data_dir.resolve()
    results = []

    def run(name, command, success):
        env = os.environ.copy()
        env["SALVIUM_AUDIT_TRACE"] = "1"
        with (root / (name + ".log")).open("w") as log:
            process = subprocess.run(command, env=env, stdout=log,
                                     stderr=subprocess.STDOUT, timeout=180)
        results.append(dict(name=name, command=list(map(str, command)),
                            exit_status=process.returncode))
        (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        if (process.returncode == 0) != success:
            raise AssertionError(f"{name}: unexpected exit status {process.returncode}")
        return (root / (name + ".log")).read_text()

    raw = root / "prefix.raw"
    run("export", [binary / "salvium-blockchain-export", "--data-dir", source,
        "--output-file", raw, "--block-stop", "3", "--log-level", "1"], True)

    def command(data, file, end):
        return [binary / "salvium-blockchain-import", "--data-dir", root / data,
            "--input-file", file, "--block-stop", str(end), "--batch-size", "1",
            "--fast-block-sync", "0", "--disable-dns-checkpoints", "--offline",
            "--check-updates", "disabled", "--log-level", "1"]

    run("prefix", command("resume-data", raw, 2), True)
    resumed = run("inclusive-last-block", command("resume-data", raw, 3), True)
    if "AUDIT_BLOCK height=3 " not in resumed:
        raise AssertionError("The inclusive final source block was not processed")
    run("already-complete", command("resume-data", raw, 3), True)
    run("default-last-block", command("default-data", raw, 0), True)
    non_genesis = root / "non-genesis.raw"
    run("export-non-genesis", [binary / "salvium-blockchain-export", "--data-dir", source,
        "--output-file", non_genesis, "--block-start", "1", "--block-stop", "3"], True)
    exact_start = run("source-starts-at-next-block", command("exact-start-data", non_genesis, 3), True)
    if "AUDIT_BLOCK height=1 " not in exact_start or "AUDIT_BLOCK height=3 " not in exact_start:
        raise AssertionError("A zero-block seek skipped the first source block")
    run("requested-end-unavailable", command("resume-data", raw, 4), False)
    run("missing-source", command("missing-data", root / "absent.raw", 3), False)
    content = raw.read_bytes()
    # Locate the last chunk from the on-disk bootstrap framing, independently
    # of the importer. The exporter writes a four-byte magic and 1024-byte header.
    chunks = []
    offset = 1028
    while offset < len(content):
        chunks.append(offset)
        size, = struct.unpack_from("<I", content, offset)
        offset += 4 + size
    assert offset == len(content) and len(chunks) == 4
    damaged = {"header": content[:1027], "body": content[:-17]}
    for partial in (1, 2, 3):
        damaged[f"chunk-header-{partial}"] = content[:chunks[-1] + partial]
    for name, data in damaged.items():
        file = root / (name + ".raw")
        file.write_bytes(data)
        run("count-" + name, [binary / "salvium-blockchain-import", "--input-file",
            file, "--count-blocks", "--data-dir", root / ("count-" + name)], False)
        # The counting preflight must fail even without an explicit ending
        # height; otherwise a truncated source can be mistaken for a shorter one.
        run("import-" + name, command("data-" + name, file, 0), False)
    print("PASS: inclusive resume, completed no-op, default end, partial headers and bodies")


if __name__ == "__main__":
    main()
