# Taintproof

A security review skill for [Claude Code](https://code.claude.com/docs/en/skills) that proves a vulnerability is exploitable before reporting it.

Scanners are fast but noisy. AI review reads code well but can miss things and can be talked out of a finding. Taintproof combines them: deterministic tools find candidates, then Claude traces each one from source to sink, dismisses what real code stops, and writes up what is left with a calculated risk score and three ways to fix it.

```text
> /taintproof src/api

Verdict: BLOCK DEPLOYMENT for src/api

| Critical | High | Medium | Low | Dismissed | Injection attempts |
| 2        | 4    | 2      | 0   | 4         | 1                  |

Full report: security-reports/api-2026-11-01.md
```

## What you get

Every review saves a Markdown report to `security-reports/`, ordered Critical to Low. Each finding includes:

- **Location and weakness:** the exact `file:line`, CWE and OWASP Top 10 category, and what detected it.
- **Risk rating:** a worked [OWASP Risk Rating](https://community.owasp.org/OWASP_Risk_Rating_Methodology) calculation of likelihood and impact, plus a CVSS baseline.
- **Exploitability proof:** the source, the path through the code, the controls found, and why they fail.
- **What Could Happen:** a concrete attack story covering the technical and business impact.
- **Three fixes:**
  - *Recommended Fix:* the most robust solution, as corrected code.
  - *Alternative Fix:* a compensating control for when the best fix isn't possible yet.
  - *User-Guided Fix:* steps for fixing it yourself, with how to confirm it worked.

The report also states what was and wasn't covered, which assumptions affect severity, which candidates were dismissed and why, and any attempts to manipulate the reviewer.

## Install

You need [Claude Code](https://code.claude.com/docs/en/overview) and Python 3.11 or newer. [Semgrep](https://semgrep.dev) is optional but strongly recommended, because without it the review falls back to a weaker search and says so in the report.

```bash
git clone https://github.com/ficcc/taintproof.git ~/.claude/skills/taintproof
uv tool install semgrep
python3 ~/.claude/skills/taintproof/scripts/update-threat-intel.py
```

The last command downloads the threat intelligence. Reviews won't start without it, because this data is generated locally rather than stored in the repository.

Check that your Python and Semgrep work together:

```bash
python3 ~/.claude/skills/taintproof/scripts/run-semgrep.py .
```

The first line should say `SEMGREP_STATUS=OK`.

<details>
<summary>Windows with Microsoft Store Python</summary>

Store Python hides `%APPDATA%\Roaming` from its child processes, which is where uv installs tools by default. If you see `uv trampoline failed to canonicalize script path`, reinstall Semgrep in a different folder:

```bash
uv tool uninstall semgrep
UV_TOOL_DIR="$HOME/.local/share/uv-tools" uv tool install semgrep
```

</details>

## Usage

Ask in plain language, such as "is this safe to deploy?", or run the command:

```text
/taintproof [path] [--allow-stale-intel] [--offline] [deployment context]
```

| Example | What it does |
|---|---|
| `/taintproof` | Reviews the current directory |
| `/taintproof src/api` | Reviews one folder, which is faster and uses fewer tokens |
| `/taintproof . internal-only service, no personal data` | Gives context that affects severity |
| `/taintproof --offline` | Skips both scanners, so no network calls are made for scanning |
| `/taintproof --allow-stale-intel` | Runs even if threat intelligence is out of date |

Business context changes severity. If your README or deployment files don't show who can reach the service and what data it holds, tell the skill, or check the Assumptions section of the report.

## How it works

1. **Intel gate:** checks that threat intelligence is under 7 days old, and pauses if not.
2. **Map the target:** finds entry points, trust boundaries and data sensitivity.
3. **Scan:** runs Semgrep and checks pinned dependencies against [OSV.dev](https://osv.dev).
4. **Manual pass:** reads for flaws scanners miss, such as broken authorization and business logic.
5. **Adjudicate:** traces every candidate from source to sink and dismisses what real code stops.
6. **Rate:** calculates OWASP risk, adjusted for flaws that are being actively exploited.
7. **Verify and report:** re-reads every cited line, then saves the report.

The review runs in a forked subagent, so your main conversation stays small. It stays read-only apart from saving the report, and it never executes, builds or installs the project.

## Staying up to date

| Part | How it stays current |
|---|---|
| Semgrep rules | Downloaded on every scan |
| Dependency advisories (OSV.dev) | Queried live on every review |
| CVE scores (NVD) | Queried live when a review needs them |
| Threat digest (CISA KEV, GitHub advisories, new NVD CVEs) | Updated when you run `update-threat-intel.py` |

Updating the digest uses no Claude tokens, so run it daily on a schedule.

**Windows Task Scheduler (PowerShell):**

```powershell
$python = (Get-Command python).Source
$script = "`"$HOME\.claude\skills\taintproof\scripts\update-threat-intel.py`""
$action = New-ScheduledTaskAction -Execute $python -Argument $script
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable
Register-ScheduledTask -TaskName "Taintproof-ThreatIntel" -Action $action -Trigger $trigger -Settings $settings
```

**macOS or Linux (cron):**

```bash
(crontab -l 2>/dev/null; echo '0 9 * * * python3 "$HOME/.claude/skills/taintproof/scripts/update-threat-intel.py"') | crontab -
```

Optional environment variables raise API rate limits: `NVD_API_KEY` and `GITHUB_TOKEN`. Each is sent only to its own service.

## Defending the reviewer

A security reviewer reads attacker-controlled code, so it is treated as a target too.

| Attack | Defense |
|---|---|
| A comment tells the AI to ignore a flaw | All file and tool content is treated as data, and the attempt is reported |
| A comment claims "sanitized upstream" | Only code that was read on the actual path counts as a control |
| `.semgrepignore` or `.gitignore` hides a file from the scanner | Both are disabled for the scan, and `.semgrepignore` is reported |
| `# nosemgrep` hides a finding | Inline suppressions are ignored and reported |
| A malicious lockfile runs code during analysis | Lockfiles are parsed as data, and no package manager is ever run |
| A poisoned advisory carries instructions | Feed text is sanitized and marked as third-party data |

## Data and privacy

Your source code is not uploaded by Taintproof's scripts. It is read by Claude as part of your normal Claude Code session.

| Service | What it receives | When |
|---|---|---|
| Semgrep registry | A request for rule packs, with metrics turned off | Each scan |
| [OSV.dev](https://osv.dev) | Package names and versions | Each review |
| NVD | CVE IDs | When looking up a CVE |
| CISA and GitHub | Public feed requests | When updating the digest |

If your package names are private, run `check-dependencies.py --dry-run` to see exactly what would be sent, or use `--offline`.

Reports describe unpatched vulnerabilities, so `security-reports/` git-ignores itself. Treat these files as sensitive.

## Limitations

- **Static analysis only.** Nothing is executed, so runtime and infrastructure issues can be missed. A clean report means nothing was found in the listed coverage, not that the code is secure. This doesn't replace a penetration test.
- **Severity can vary between runs.** Scoring is consistent in method, but findings can move a tier, because factor scores involve judgment.
- **CVSS v4.0 scores are estimates** unless they come from NVD, because a real score needs the official lookup tables.
- **Not every lockfile is supported.** `yarn.lock`, `pnpm-lock.yaml`, `pom.xml`, Gradle files, `Gemfile.lock` and `packages.lock.json` are listed as unchecked in the report.
- **`--x-ignore-semgrepignore-files` is an unstable Semgrep option.** If a future release removes it, the wrapper continues and the report shows that ignore files were honored.
- **The write restriction relies on Claude Code permissions.** Permission modes that auto-accept edits can allow writes outside `security-reports/`.
- **Large projects use more tokens.** A review of a 72-line test app used about 90,000 to 165,000 fresh tokens on Sonnet. Reviewing one folder at a time keeps this down.

## Testing

Tested on Windows 11 with Claude Code 2.1, Python 3.13, Semgrep 1.183 and Sonnet in headless mode, against a deliberately vulnerable Flask app with hidden traps: a prompt injection comment, a `nosemgrep` suppression, a false "sanitized upstream" comment, a safe query that looks unsafe, and an authorization flaw scanners can't see.

The final test run passed all 15 graded checks, compared with 6 of 14 for an unaided review. Interactive sessions, macOS and Linux have not been tested yet.

## Repository layout

```text
SKILL.md                      The review workflow and report template
references/
  risk-rating.md              OWASP factors, matrix and CVSS rules
  review-checklist.md         Manual review areas and fallback search patterns
  dynamic-rules.md            Generated threat digest (not in git)
  kev-index.tsv               Generated full KEV index (not in git)
scripts/
  update-threat-intel.py      Updates the digest, checks status, looks up CVEs
  run-semgrep.py              Runs Semgrep so the target can't disable it
  check-dependencies.py       Checks lockfiles against OSV.dev
  intel-status.sh             Reports digest freshness when a review starts
  intel_common.py             Shared helpers
```

The scripts use only the Python standard library.

## License

[MIT](LICENSE)
