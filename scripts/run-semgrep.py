#!/usr/bin/env python3
"""Run Semgrep so that the code under review cannot switch the scanner off.

  run-semgrep.py [target]

The target controls .semgrepignore, .gitignore and inline nosemgrep comments, and each one
silently hides findings. This wrapper disables all three, reports them as evasion signals,
and prints compact candidates for adjudication. Always exits 0: the first line says what
happened. Rules come from the Semgrep registry; no source code is uploaded.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from intel_common import clean, use_utf8_stdout

RULE_PACKS = ["p/security-audit", "p/owasp-top-ten", "p/secrets"]
SKIPPED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
    "node_modules", "bower_components", "vendor", "dist", "build", "target",
}
UNSTABLE_IGNORE_FLAG = "--x-ignore-semgrepignore-files"
SCAN_TIMEOUT_SECONDS = 900
RULE_TIMEOUT_SECONDS = "30"
MAX_CANDIDATES = 200
MAX_SIGNALS = 40
MAX_SIGNAL_FILE_BYTES = 2 * 1024 * 1024
SUPPRESSION = re.compile(r"\b(nosemgrep|nosem|nosec)\b", re.IGNORECASE)
TEXT_SUFFIXES_TO_SKIP = {".png", ".jpg", ".gif", ".pdf", ".zip", ".gz", ".exe", ".dll", ".lock"}
STORE_PYTHON_HINT = (
    "Hint: Microsoft Store Python hides %APPDATA%\\Roaming from its child processes, and uv "
    "keeps tools there. Reinstall Semgrep elsewhere: uv tool uninstall semgrep, then "
    "UV_TOOL_DIR=~/.local/share/uv-tools uv tool install semgrep"
)


def find_semgrep():
    found = shutil.which("semgrep")
    if found:
        return found
    for name in ("semgrep.exe", "semgrep"):
        candidate = Path.home() / ".local" / "bin" / name
        if candidate.exists():
            return str(candidate)
    return None


def build_command(semgrep, ignore_flag):
    command = [semgrep, "scan", "--json", "--quiet", "--metrics=off", "--disable-nosem"]
    command += ["--no-git-ignore", f"--timeout={RULE_TIMEOUT_SECONDS}"]
    if ignore_flag:
        command.append(UNSTABLE_IGNORE_FLAG)
    for pack in RULE_PACKS:
        command += ["--config", pack]
    for directory in sorted(SKIPPED_DIRS):
        command.append(f"--exclude={directory}")
    return command + ["."]


def run_scan(semgrep, target, ignore_flag):
    return subprocess.run(
        build_command(semgrep, ignore_flag),
        cwd=target,
        env=dict(os.environ, PYTHONUTF8="1"),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=SCAN_TIMEOUT_SECONDS,
    )


def scan_with_fallback(semgrep, target):
    """Retry without the unstable flag, which Semgrep may remove in any release."""
    result = run_scan(semgrep, target, ignore_flag=True)
    if result.returncode in (0, 1):
        return result, True
    return run_scan(semgrep, target, ignore_flag=False), False


def evasion_signals(target):
    signals = []
    for root, directories, files in os.walk(target):
        directories[:] = [d for d in directories if d not in SKIPPED_DIRS]
        for name in files:
            path = Path(root) / name
            relative = path.relative_to(target).as_posix()
            if name == ".semgrepignore":
                patterns = path.read_text(encoding="utf-8", errors="replace").split()
                signals.append(f"{relative}: tries to exclude {clean(' '.join(patterns), 160)}")
                continue
            if path.suffix.lower() in TEXT_SUFFIXES_TO_SKIP:
                continue
            try:
                if path.stat().st_size > MAX_SIGNAL_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for number, line in enumerate(content.splitlines(), start=1):
                if SUPPRESSION.search(line):
                    signals.append(f"{relative}:{number}: inline suppression: {clean(line, 100)}")
    return signals


def first_cwe(metadata):
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    return clean(str(cwe).split(":")[0], 12) or "n/a"


def print_candidates(results):
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    results.sort(key=lambda r: (order.get(r["extra"].get("severity"), 3), r["path"], r["start"]["line"]))
    for number, finding in enumerate(results[:MAX_CANDIDATES], start=1):
        extra = finding["extra"]
        metadata = extra.get("metadata") or {}
        print(
            f"[{number}] {clean(finding['path'], 120)}:{finding['start']['line']}-"
            f"{finding['end']['line']} severity={clean(extra.get('severity'), 8)} "
            f"cwe={first_cwe(metadata)} confidence={clean(metadata.get('confidence'), 8) or 'n/a'} "
            f"rule={clean(finding['check_id'], 120)}"
        )
        print(f"    {clean(extra.get('message'), 220)}")
    if len(results) > MAX_CANDIDATES:
        print(f"... {len(results) - MAX_CANDIDATES} more candidates were cut; review by rule.")


def main():
    use_utf8_stdout()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", nargs="?", default=".")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"SEMGREP_STATUS=ERROR reason=target_is_not_a_directory path={clean(target, 200)}")
        return 0

    signals = evasion_signals(target)
    semgrep = find_semgrep()
    if semgrep is None:
        print("SEMGREP_STATUS=NOT_INSTALLED")
        print("Install with: uv tool install semgrep  (or: pipx install semgrep)")
    else:
        try:
            result, ignore_files_disabled = scan_with_fallback(semgrep, target)
        except subprocess.TimeoutExpired:
            print(f"SEMGREP_STATUS=ERROR reason=timeout_after_{SCAN_TIMEOUT_SECONDS}s")
            result = None
        if result is not None:
            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError:
                print(f"SEMGREP_STATUS=ERROR exit={result.returncode}")
                print(f"stderr: {clean(result.stderr[-500:], 500)}")
                if "WindowsApps" in sys.executable and "trampoline" in result.stderr:
                    print(STORE_PYTHON_HINT)
                report = None
            if report is not None:
                findings = report.get("results") or []
                errors = report.get("errors") or []
                scanned = (report.get("paths") or {}).get("scanned") or []
                print(
                    f"SEMGREP_STATUS=OK version={clean(report.get('version'), 12)} "
                    f"rules={','.join(RULE_PACKS)} files_scanned={len(scanned)} "
                    f"candidates={len(findings)} scan_errors={len(errors)} "
                    f"inline_suppressions_honored=no ignore_files_honored="
                    f"{'no' if ignore_files_disabled else 'YES_FLAG_REMOVED'}"
                )
                for error in errors[:10]:
                    print(f"scan error: {clean(error.get('path'), 100)}: {clean(error.get('type'), 40)}")
                print("--- CANDIDATES (unverified; adjudicate each one) ---")
                print_candidates(findings)

    print("--- EVASION SIGNALS ---")
    for signal in signals[:MAX_SIGNALS]:
        print(signal)
    if len(signals) > MAX_SIGNALS:
        print(f"... {len(signals) - MAX_SIGNALS} more")
    if not signals:
        print("none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
