# 🔱 Talos-Guard™

> **"Trust, but Verify."**

**Talos-Guard™** is a static analysis tool designed to audit OpenClaw `SKILL.md` files and scripts. It mitigates supply chain attacks by detecting malicious patterns *before* installation.

## ⚠️ Disclaimer
**Talos-Guard™ is a heuristic aid, not a guarantee.**
It detects known signatures of malicious behavior. It cannot detect all malware. **You are responsible for reviewing code.**

## 🚀 Usage

### Run Locally (Zero Install)
```bash
npx talos-guard https://example.com/SKILL.md
```

### Install Globally
```bash
npm install -g talos-guard
talos-guard ./my-skills/
```

## 🛡️ Signatures

Talos-Guard™ scans for:
*   🔴 **CRITICAL:** Exfiltration endpoints (`webhook.site`), SSH/AWS credential theft, C2 IPs.
*   🟡 **HIGH:** Obfuscated code (`base64`, `eval`), reading `.env` files, piping to shell.
*   🔵 **MEDIUM:** Network capabilities (`curl`, `wget`), file writes.

## License
MIT
Copyright (c) 2026 Ca7ai (Talos)
