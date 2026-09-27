#!/usr/bin/env python3
"""Record a synthetic-fixture validation command and its exact source identity."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def source_identity():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT)
    digest = hashlib.sha256()
    verification_digest = hashlib.sha256()
    names = git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    for name in sorted(set(names.split(b"\0")) - {b""}):
        path = ROOT / os.fsdecode(name)
        if path.is_symlink():
            content = os.fsencode(os.readlink(path))
        else:
            content = path.read_bytes() if path.is_file() else b"<absent>"
        frame = (name + b"\0" + str(path.lstat().st_mode if path.exists() else 0).encode()
                 + b"\0" + str(len(content)).encode() + b"\0" + content)
        digest.update(frame)
        # The human ledger is updated after observing results. Keep all source,
        # tests, workflows, locks and other documentation in this second digest.
        if name != b"docs/remediation.md":
            verification_digest.update(frame)
    return {
        "commit": git("rev-parse", "HEAD").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "dirty": bool(git("status", "--porcelain")),
        "source_sha256": digest.hexdigest(),
        "verification_source_sha256": verification_digest.hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    parser.add_argument("--signing-category", default="not-applicable")
    parser.add_argument("--fixture", default="synthetic/local")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.timeout <= 0 or not re.fullmatch(r"[a-zA-Z0-9-]+", args.suite):
        parser.error("a command and positive timeout are required")
    args.output.mkdir(parents=True, exist_ok=True)
    log = args.output / (args.suite + ".log")
    report_path = args.output / (args.suite + ".json")
    if log.exists() or report_path.exists():
        parser.error("use a new suite name or output directory; evidence is not overwritten")
    report = {"schema_version": 1, "suite": args.suite, "source": source_identity(),
              "command": command, "platform": platform.platform(),
              "architecture": platform.machine(), "fixture": args.fixture,
              "started": datetime.datetime.now(datetime.UTC).isoformat(),
              "limitations": ["Local execution; no independent audit or native-runtime inference."]}
    report["artifacts"] = []
    report["toolchains"] = {}
    for name, version_command in {"rust": ["rustc", "--version"], "node": ["node", "--version"],
                          "pnpm": ["pnpm", "--version"], "python": ["python3", "--version"]}.items():
        try:
            report["toolchains"][name] = subprocess.check_output(version_command, stderr=subprocess.STDOUT, timeout=30).decode().strip()
        except (OSError, subprocess.SubprocessError):
            report["toolchains"][name] = "unavailable"
    started = time.monotonic()
    result = "failed"
    reason = None
    output_size = 0
    output_limit = 16 * 1024 * 1024
    output_errors = []
    try:
        with log.open("xb") as output:
            child = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=os.name == "posix")
            def drain():
                nonlocal output_size
                try:
                    while block := child.stdout.read1(8192):
                        output.write(block[:max(0, output_limit - output_size)])
                        output.flush()
                        output_size += len(block)
                except OSError:
                    output_errors.append("LogWriteFailed")
            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            try:
                code = child.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], check=False, capture_output=True)
                child.wait()
                raise
            finally:
                reader.join(timeout=5)
            if reader.is_alive() or output_errors:
                if os.name == "posix":
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                raise OSError("command left its output pipe open")
        if output_size > output_limit:
            code, reason = 1, "OutputLimitExceeded"
        result = "passed" if code == 0 else "failed"
    except (OSError, subprocess.TimeoutExpired) as error:
        code, reason = 1, type(error).__name__
    for path in args.artifact:
        if not path.is_file() or path.is_symlink():
            result, code, reason = "failed", 1, "ArtifactMissingOrUnsafe"
            continue
        with path.open("rb") as artifact:
            report["artifacts"].append({"filename": path.name,
                "path": str(path.resolve().relative_to(ROOT)) if path.resolve().is_relative_to(ROOT) else path.name,
                "size": path.stat().st_size,
                "sha256": hashlib.file_digest(artifact, "sha256").hexdigest(),
                "signing_category": args.signing_category})
    report.update(result=result, exit_code=code, reason=reason,
                  ended=datetime.datetime.now(datetime.UTC).isoformat(),
                  elapsed_seconds=round(time.monotonic() - started, 3),
                  log=log.name, log_truncated=output_size > output_limit, source_after=source_identity())
    report["source_changed_during_run"] = report["source"]["source_sha256"] != report["source_after"]["source_sha256"]
    report["verification_source_changed_during_run"] = report["source"]["verification_source_sha256"] != report["source_after"]["verification_source_sha256"]
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{args.suite}: {result}; {log}")
    return code if code > 0 else (1 if code < 0 else 0)


if __name__ == "__main__":
    raise SystemExit(main())
