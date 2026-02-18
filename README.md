# 🦞 GuardClaw v4.3.0
### The Intelligent Security Shield for Autonomous AI Agents

GuardClaw is a localized security middleware designed to protect users and AI agents (like **OpenClaw**) from prompt injections, data exfiltration, and malicious tool-execution.

**100% Local | Privacy-First | Optimized for Ollama**

---

## 🛡️ Why GuardClaw?
Autonomous agents have access to your files, browser, and terminal. Malicious websites or files can contain "hidden instructions" that trick your agent into leaking credentials (like `~/.openclaw/` keys) or executing harmful commands. GuardClaw sits in the middle to stop these attacks.



## ✨ Key Features
- ⚡ **Adaptive Fast-Scan:** Instant static rules that only trigger the AI model if a threat is suspected (Perfect for low-VRAM GPUs like the GTX 1050).
- 🕵️ **Credential Protection:** Specifically blocks attempts to harvest local API keys and session tokens.
- 🎭 **PII Masking:** Automatically redacts emails, credit cards, and personal data before processing.
- 👮 **Three Guarding Modes:**
  - `nanny`: Automatic blocking of all high-risk threats (Headless/Automated).
  - `bouncer`: Asks for confirmation on medium/high threats (Balanced).
  - `junior`: Log-only mode for researchers and developers.

## 🚀 Quick Start
1. Clone the repo:
   ```bash
   git clone [https://github.com/acria9/GuardClaw.git](https://github.com/acria9/GuardClaw.git)
   cd GuardClaw