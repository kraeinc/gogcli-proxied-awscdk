import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

POLICY = json.loads((Path(__file__).resolve().parents[1] / ".privacy-policy.json").read_text())
TOKENS = re.compile(rb"/(?:home|Users)/[A-Za-z0-9._-]+|[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|\b[0-9]{12,13}\b|\b[A-Za-z][A-Za-z0-9_.+-]*\b")


def violations(path, content):
    findings = []
    if path not in POLICY["allowed_paths"] and any(fnmatch.fnmatchcase(path, pattern) for pattern in POLICY["prohibited_paths"]):
        findings.append("private operational file")
    for token in TOKENS.findall(content):
        token = token.rstrip(b".")
        candidates = {token.lower()}
        domain = token.rsplit(b"@", 1)[-1].lower()
        labels = domain.split(b".")
        candidates.update(b".".join(labels[index:]) for index in range(len(labels) - 1))
        if any(hashlib.sha256(value).hexdigest() in POLICY["identifier_sha256"] for value in candidates):
            findings.append("personal or deployment identifier")
            break
    return findings


def git(*args):
    return subprocess.check_output(["git", *args])


def scan(staged):
    paths = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split(b"\0") if staged else git("ls-files", "-z").split(b"\0")
    failed = False
    for raw_path in paths:
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", "surrogateescape")
        content = git("show", ":" + path)
        for finding in violations(path, content):
            print(f"{path}: {finding}", file=sys.stderr)
            failed = True
    return int(failed)


def scan_history(revision):
    failed = False
    paths = git("log", revision, "--format=", "--name-only", "-z").split(b"\0")
    for raw_path in set(paths):
        path = raw_path.lstrip(b"\n").decode("utf-8", "surrogateescape")
        if path and violations(path, b""):
            print(f"{path}: private operational file in history", file=sys.stderr)
            failed = True
    objects = git("rev-list", "--objects", revision).splitlines()
    process = subprocess.Popen(["git", "cat-file", "--batch"], cwd=git("rev-parse", "--absolute-git-dir").decode().strip(), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        for record in objects:
            oid, _, raw_path = record.partition(b" ")
            process.stdin.write(oid + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().split()
            if len(header) != 3:
                raise RuntimeError("Could not read Git history object")
            content = process.stdout.read(int(header[2]))
            process.stdout.read(1)
            if header[1] != b"blob":
                continue
            path = raw_path.decode("utf-8", "surrogateescape") or oid.decode()
            for finding in violations(path, content):
                if finding == "private operational file":
                    continue
                print(f"{path}: {finding} in history", file=sys.stderr)
                failed = True
    finally:
        process.stdin.close()
        process.stdout.close()
        if process.wait() != 0:
            raise RuntimeError("Git history scan failed")
    return int(failed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--history", nargs="?", const="--all")
    args = parser.parse_args()
    sys.exit(scan_history(args.history) if args.history else scan(args.staged))
