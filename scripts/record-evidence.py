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


def artifact_record(path, category, role):
    if not path.is_file() or path.is_symlink():
        raise OSError('ArtifactMissingOrUnsafe')
    with path.open('rb') as artifact:
        digest = hashlib.file_digest(artifact, 'sha256').hexdigest()
        size = os.fstat(artifact.fileno()).st_size
    return {'filename': path.name,
            'path': str(path.resolve().relative_to(ROOT)) if path.resolve().is_relative_to(ROOT) else path.name,
            'size': size, 'sha256': digest, 'signing_category': category, 'role': role}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--artifact", type=Path, action="append", default=[], help="Artifact produced by a build")
    parser.add_argument("--tested-artifact", type=Path, action="append", default=[],
                        help="Existing input that must have identical bytes before and after the check")
    parser.add_argument("--frozen-source", action="store_true",
                        help="Fail qualification if the source is dirty or changes during the command")
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
    report["tested_artifacts_before"] = []
    report["frozen_source_required"] = args.frozen_source
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
        report['tested_artifacts_before'] = [artifact_record(p, args.signing_category, 'tested-input')
                                             for p in args.tested_artifact]
        if args.frozen_source and report['source']['dirty']:
            raise OSError('SourceNotFrozen')
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
        code = 1
        reason = str(error) if str(error) in ('ArtifactMissingOrUnsafe', 'SourceNotFrozen') else type(error).__name__
    for path, role in [(p, 'tested-input') for p in args.tested_artifact] + [(p, 'build-output') for p in args.artifact]:
        try:
            report['artifacts'].append(artifact_record(path, args.signing_category, role))
        except OSError:
            result, code, reason = "failed", 1, "ArtifactMissingOrUnsafe"
    tested_after = [a for a in report['artifacts'] if a['role'] == 'tested-input']
    if reason != 'ArtifactMissingOrUnsafe' and tested_after != report['tested_artifacts_before']:
        result, code, reason = 'failed', 1, 'TestedArtifactChanged'
    report.update(result=result, exit_code=code, reason=reason,
                  ended=datetime.datetime.now(datetime.UTC).isoformat(),
                  elapsed_seconds=round(time.monotonic() - started, 3),
                  log=log.name, log_truncated=output_size > output_limit, source_after=source_identity())
    report["source_changed_during_run"] = report["source"]["source_sha256"] != report["source_after"]["source_sha256"]
    report["verification_source_changed_during_run"] = report["source"]["verification_source_sha256"] != report["source_after"]["verification_source_sha256"]
    if args.frozen_source and (report['source_after']['dirty'] or report['source_changed_during_run']):
        report.update(result='failed', exit_code=1, reason='SourceNotFrozen')
        code = 1
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{args.suite}: {report['result']}; {log}")
    return code if code > 0 else (1 if code < 0 else 0)


if __name__ == "__main__":
    raise SystemExit(main())
