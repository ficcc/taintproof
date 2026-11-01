# Review Checklist

## Manual pass

Pattern matching rarely sees these, because each one depends on what the code was meant to do. Read the relevant code rather than grepping alone.

| Area | Look for |
| --- | --- |
| Authorization | Object lookups by client-supplied ID with no owner or tenant check (IDOR); handlers missing the guard their siblings have; role checks only in the UI |
| Authentication | Routes with no login requirement that return private data; weak password storage; missing rate limits; session fixation; JWTs with unverified signature, `none` algorithm or no expiry |
| Mass assignment | Request bodies copied into models or sessions, letting callers set `role`, `user_id` or `price` |
| Secrets | Keys, tokens and passwords in source, config, fixtures and git-tracked env files |
| Business logic | Price or quantity tampering, skipped workflow steps, race conditions on balances or redemptions, replayable actions |
| File handling | Path traversal, unrestricted upload, archive extraction outside the target directory |
| Outbound requests | SSRF through URLs or hosts taken from input, including redirects and webhooks |
| Cryptography | Homemade crypto, ECB mode, static IVs, `Math.random` for tokens, disabled TLS verification |
| Configuration | Debug mode in production paths, permissive CORS with credentials, missing cookie flags, verbose errors, public cloud storage |
| LLM features | Untrusted text reaching a prompt, or model output reaching a tool, SQL, shell or HTML sink (CWE-1427) |

## Grep sweep

Use this only when Semgrep could not run. It is a weak substitute, so the report must still mark the deterministic scan as NOT RUN. Every hit is a candidate that goes through adjudication.

| Weakness | Pattern for the Grep tool |
| --- | --- |
| Command injection | `os\.system\|subprocess.*shell=True\|child_process\.exec\|Runtime\.getRuntime\(\)\.exec\|shell_exec\|` |
| Code execution | `\beval\(\|\bexec\(\|new Function\(\|vm\.runIn` |
| Deserialization | `pickle\.loads?\|yaml\.load\(\|marshal\.loads\|ObjectInputStream\|unserialize\(\|BinaryFormatter` |
| SQL injection | `(SELECT\|INSERT\|UPDATE\|DELETE).*(\+\|%s\|\$\{\|\{[a-z_]+\})\|\.raw\(\|\.execute\(f"` |
| XSS | `innerHTML\|dangerouslySetInnerHTML\|v-html\|\|\s*safe\b\|document\.write\|mark_safe` |
| Path traversal | `open\(.*(request\|req\.\|params)\|sendFile\(\|send_file\(\|\.\./` |
| SSRF | `requests\.(get\|post)\(.*(request\|req\.\|url)\|fetch\(.*(req\.\|params)\|urlopen\(` |
| Weak crypto | `\bmd5\b\|\bsha1\b\|\bDES\b\|\bRC4\b\|ECB\|verify\s*=\s*False\|rejectUnauthorized:\s*false` |
| Secrets | `(api[_-]?key\|secret\|password\|token)\s*[:=]\s*["'][^"']{8,}\|AKIA[0-9A-Z]{16}\|-----BEGIN .*PRIVATE KEY` |
| Scanner evasion | `nosemgrep\|nosec\|eslint-disable.*security` |
