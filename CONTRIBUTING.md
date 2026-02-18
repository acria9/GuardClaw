# Contributing to GuardClaw

Thank you for your interest in making GuardClaw better. This is a security tool, so contributions are held to a high bar — but the bar is achievable and the process is straightforward.

---

## Ways to contribute

- **Add detection rules** — new CODE_PATTERNS or PROMPT_INJECTION_PATTERNS
- **Improve the UI** — better layouts, accessibility, dark/light theme support
- **Add Ollama models** — test and document which models work best for security analysis
- **Write tests** — we need a proper test suite for the StaticScanner
- **Fix bugs** — check the issue tracker
- **Improve documentation** — translations, examples, tutorials
- **Report vulnerabilities** — see [SECURITY.md](SECURITY.md) for the right process

---

## Ground rules

1. **No breaking changes without discussion.** Open an issue first if you're changing the scanner logic, the history format, or the prompt structure.

2. **Security contributions must include a test case.** If you're adding a new detection rule, include sample input that triggers it and sample input that should not.

3. **Don't add external API calls without a clear opt-in.** GuardClaw's core promise is that it works 100% locally. Features that phone home must be strictly opt-in, clearly labeled, and disabled by default.

4. **Keep the three modes coherent.** Nanny, Bouncer, and Junior have distinct personalities and threat tolerances. New features should respect that distinction.

5. **False positives matter.** A security tool that cries wolf too often trains users to ignore warnings. When adding detection rules, consider the false positive rate.

---

## Getting started

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/guardclaw.git
cd guardclaw

# Install dependencies
pip install customtkinter pyperclip requests

# Run GuardClaw
python guardclaw.py
```

---

## Adding a detection rule

Detection rules live in `CODE_PATTERNS` (for code/commands) and `PROMPT_INJECTION_PATTERNS` (for AI manipulation attempts).

A `CODE_PATTERNS` entry looks like this:

```python
("CATEGORIA", "severity", r"regex_pattern", "Human-readable description"),
```

- **CATEGORIA:** All-caps string identifying the threat class (e.g. `"RCE"`, `"MALWARE"`)
- **severity:** One of `"low"`, `"medium"`, `"high"`, `"critical"`
- **regex_pattern:** Must be tested against both malicious and benign inputs
- **description:** Should explain what the threat does, not just name it

When submitting a new rule in a PR, include:
- The rule itself
- An example of malicious input that triggers it
- An example of benign input that should NOT trigger it
- The severity rationale

---

## Pull Request checklist

- [ ] Code runs without errors (`python guardclaw.py`)
- [ ] No new external network calls added without opt-in
- [ ] New detection rules include test input examples in the PR description
- [ ] Docstrings updated if you changed public functions
- [ ] Version bump not required (maintainer will handle releases)

---

## Code style

- Python 3.9+ compatible
- Follow the existing style — Consolas font references in UI, Spanish UI strings, English code comments
- No new hard dependencies without discussion (every new `pip install` is friction for users)

---

## Questions?

Open a GitHub Discussion or an issue tagged `question`. We're friendly.
