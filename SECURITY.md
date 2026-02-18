# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 4.1.x | ✅ Yes |
| 4.0.x | ⚠️ Security fixes only |
| < 4.0 | ❌ No |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

A public issue exposes all users to risk before a fix is available.

### How to report

1. **Email:** Send a description of the vulnerability to the project maintainer. Include:
   - A clear description of the vulnerability
   - Steps to reproduce it
   - The potential impact
   - Any suggested fixes (optional but appreciated)

2. **GitHub private advisory (preferred):** Use GitHub's built-in private security advisory system:
   - Go to the **Security** tab of this repository
   - Click **"Report a vulnerability"**
   - Fill in the details

### What to expect

- **Acknowledgment** within 48 hours
- **Status update** within 7 days (confirmed, investigating, or not reproducible)
- **Fix and coordinated disclosure** as quickly as possible — typically within 30 days for critical issues
- **Credit** in the changelog if you want it

---

## Scope

Vulnerabilities we want to know about:

- Bypasses of detection rules that could be weaponized
- Path traversal or arbitrary file read/write in CLI mode
- ReDoS (regular expression denial of service) in the scanner
- Unsafe deserialization or code execution via malformed history files
- Race conditions that could cause incorrect threat assessment
- Sensitive data leaks in history or logs

Out of scope:

- False positives / false negatives in threat detection (these are bugs, not security issues — open a regular issue)
- UI cosmetic bugs
- Vulnerabilities in Ollama itself (report those to the [Ollama project](https://github.com/ollama/ollama))

---

## Philosophy

GuardClaw is a security tool. We hold it to a higher standard than typical software. We commit to:

- Treating security reports with priority
- Being transparent about vulnerabilities after fixes are released
- Not breaking the trust of users who rely on this tool to protect them
