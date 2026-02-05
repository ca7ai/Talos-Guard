#!/usr/bin/env node

/**
 * Talos-Guard™
 * "Trust, but Verify."
 * 
 * Copyright (c) 2026 Ca7ai (Talos)
 * Licensed under MIT. See LICENSE file.
 */

const fs = require('fs');
const https = require('https');
const path = require('path');
const { promisify } = require('util');

const readFile = promisify(fs.readFile);
const stat = promisify(fs.stat);

// ANSI Colors
const C = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  bold: "\x1b[1m",
  dim: "\x1b[2m"
};

// --- CONFIGURATION ---
const VERSION = "1.0.0-alpha";
const DISCLAIMER = `
${C.yellow}${C.bold}⚠️  DISCLAIMER & LIMITATION OF LIABILITY ⚠️${C.reset}
Talos-Guard™ is a heuristic analysis tool provided "AS IS". It detects ${C.bold}known${C.reset}
threat patterns but cannot guarantee safety. Absence of evidence is not evidence
of absence. You are solely responsible for reviewing code before installation.
`;

// --- SIGNATURE DATABASE ---
const SIGNATURES = [
  // CRITICAL: Active Exfiltration / C2
  { id: 'NET_WEBHOOK', level: 'CRITICAL', pattern: /webhook\.site|pipedream\.net|requestbin|interactsh/i, desc: 'Known exfiltration endpoint detected' },
  { id: 'NET_IP_RAW', level: 'CRITICAL', pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, desc: 'Hardcoded IP address (potential C2)' },
  { id: 'FS_SSH_KEY', level: 'CRITICAL', pattern: /\.ssh\/(id_rsa|id_ed25519|known_hosts)/, desc: 'Accessing SSH private keys' },
  { id: 'FS_AWS_CRED', level: 'CRITICAL', pattern: /\.aws\/credentials/, desc: 'Accessing AWS credentials' },
  
  // HIGH: Suspicious Behavior
  { id: 'ENV_READ', level: 'HIGH', pattern: /(cat|grep|printenv|env).*\.env/, desc: 'Reading sensitive .env files' },
  { id: 'ENV_JSON', level: 'HIGH', pattern: /credentials\.json|client_secret\.json/, desc: 'Accessing credential JSON files' },
  { id: 'OBF_EVAL', level: 'HIGH', pattern: /eval\s*\(/, desc: 'Dynamic code execution (eval)' },
  { id: 'OBF_BASE64', level: 'HIGH', pattern: /base64\s+(-d|--decode)/, desc: 'Base64 decoding (possible obfuscation)' },
  { id: 'SHELL_PIPE', level: 'HIGH', pattern: /\|\s*(sh|bash|zsh)/, desc: 'Piping content directly to shell' },
  { id: 'NET_CURL_UPLOAD', level: 'HIGH', pattern: /curl.*-F|curl.*--data|curl.*-d/, desc: 'Data exfiltration via cURL' },
  
  // MEDIUM: Capabilities to Watch
  { id: 'NET_GENERIC', level: 'MEDIUM', pattern: /curl|wget|fetch\(/, desc: 'Generic network access' },
  { id: 'FS_WRITE', level: 'MEDIUM', pattern: />\s*\/|write\(/, desc: 'File system write detected' },
];

// --- COMPONENTS ---

// 1. Fetcher
async function fetchContent(target) {
  if (target.startsWith('http')) {
    return new Promise((resolve, reject) => {
      https.get(target, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Failed to fetch URL: HTTP ${res.statusCode}`));
          return;
        }
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
  } else {
    // Local file
    return readFile(target, 'utf8');
  }
}

// 2. Parser (Extract code blocks from Markdown)
function extractCodeBlocks(markdown) {
  const blocks = [];
  const regex = /```(\w*)\n([\s\S]*?)```/g;
  let match;
  while ((match = regex.exec(markdown)) !== null) {
    blocks.push({
      lang: match[1] || 'txt',
      code: match[2],
      start: match.index
    });
  }
  return blocks;
}

// 3. Analyzer
function analyze(content, filename) {
  const findings = [];
  
  // Scan full content (for things outside code blocks too, just in case)
  const lines = content.split('\n');
  lines.forEach((line, idx) => {
    SIGNATURES.forEach(sig => {
      if (sig.pattern.test(line)) {
        findings.push({
          file: filename,
          line: idx + 1,
          content: line.trim(),
          signature: sig
        });
      }
    });
  });
  
  return findings;
}

// 4. Reporter
function printReport(findings, target) {
  console.log(`\n${C.bold}🔎 SCAN REPORT: ${target}${C.reset}`);
  console.log('---------------------------------------------------');

  if (findings.length === 0) {
    console.log(`${C.green}✅  PASS: No threat signatures detected.${C.reset}`);
    console.log(`${C.dim}    (This does not guarantee the file is safe.)${C.reset}\n`);
    return true; // Pass
  }

  let criticalCount = 0;
  let highCount = 0;

  findings.forEach(f => {
    let color = C.blue;
    if (f.signature.level === 'CRITICAL') { color = C.red; criticalCount++; }
    if (f.signature.level === 'HIGH') { color = C.yellow; highCount++; }
    
    console.log(`${color}[${f.signature.level}] ${f.signature.desc}${C.reset}`);
    console.log(`    Location: Line ${f.line}`);
    console.log(`    Match:    ${C.dim}${f.content.substring(0, 60)}${f.content.length > 60 ? '...' : ''}${C.reset}`);
  });

  console.log('---------------------------------------------------');
  console.log(`${C.bold}SUMMARY:${C.reset} ${findings.length} issues found.`);
  
  if (criticalCount > 0) {
    console.log(`\n${C.red}${C.bold}⛔  BLOCKED: Critical threats detected.${C.reset}`);
    return false; // Fail
  } else if (highCount > 0) {
    console.log(`\n${C.yellow}${C.bold}⚠️  WARNING: High-risk patterns detected. Review manually.${C.reset}`);
    return false; // Fail/Warn
  } else {
    console.log(`\n${C.blue}ℹ️  INFO: Low-risk capabilities detected.${C.reset}`);
    return true; // Pass (with info)
  }
}

// --- MAIN LOOP ---
async function main() {
  console.log(`${C.cyan}${C.bold}🔱 Talos-Guard™ v${VERSION}${C.reset}`);
  console.log(DISCLAIMER);

  const target = process.argv[2];
  if (!target) {
    console.error("Usage: talos-guard <url_or_file>");
    process.exit(1);
  }

  try {
    console.log(`[+] Fetching: ${target}...`);
    const content = await fetchContent(target);
    
    console.log(`[+] Analyzing ${content.length} bytes...`);
    const findings = analyze(content, target);
    
    const passed = printReport(findings, target);
    
    if (!passed) process.exit(1);
    process.exit(0);
    
  } catch (err) {
    console.error(`${C.red}ERROR: ${err.message}${C.reset}`);
    process.exit(1);
  }
}

main();
