# Phishing Email Analyzer

![tests](https://github.com/prajwal-sharma-cyber/phishing-email-analyzer/actions/workflows/tests.yml/badge.svg) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

A command-line tool that does the first ten minutes of a SOC analyst's phishing triage automatically. Give it a saved `.eml` file and it checks authentication, sender spoofing, routing, links, attachments and language, then gives a verdict and writes a Markdown report.

Standard library only. Nothing in the email is opened, clicked or executed.

## What it checks

| Area | Checks |
|---|---|
| Authentication | SPF, DKIM and DMARC results from `Authentication-Results` |
| Sender | `From` vs `Reply-To` vs `Return-Path`; display name claiming a brand the address does not belong to |
| Routing | `Received` chain, originating IP, missing reverse DNS |
| Links | plain HTTP, raw IPs, punycode, risky TLDs, look-alike brands (`micros0ft`), link text showing a different domain |
| Attachments | SHA-256 hash (to search in VirusTotal yourself), macro and script types, double extensions such as `.pdf.zip` |
| Language | urgency and threats, requests to verify passwords or "enable content" |

Each finding adds points. **0-3 CLEAN, 4-7 SUSPICIOUS, 8+ MALICIOUS.**

## Quick start

```bash
git clone https://github.com/prajwal-sharma-cyber/phishing-email-analyzer.git
cd phishing-email-analyzer

python src/email_analyzer.py samples/02-credential-phish.eml
python src/email_analyzer.py samples/ --report reports/
```

## Sample output

```text
02-credential-phish.eml
Subject: URGENT: Your mailbox will be suspended within 24 hours
From:    Microsoft 365 Security <no-reply@microsoft.com>
VERDICT: MALICIOUS  (score 22)
------------------------------------------------------------------------
 [X] auth       SPF fail
 [!] auth       DKIM none
 [X] auth       DMARC fail
 [X] sender     Reply-To (outlook-support.example-bulk.top) differs from From (microsoft.com) - replies go to someone else
 [X] links      look-alike of 'microsoft' in micros0ft-365-verify.example-bulk.top
 [X] links      link text shows login.microsoftonline.com but goes to micros0ft-365-verify.example-bulk.top
 [!] language   Urgency / pressure: act now, immediately, permanent, suspended, urgent
```

The `From` header says microsoft.com, but DMARC failed, so Microsoft did not send it. That one line is the most important finding in most phishing investigations.

## Analysing your own emails safely

1. In Gmail: open the email > three dots > **Download message** (saves `.eml`).
   In Outlook on the web: open the email > **...** > **Download** (or forward it as an attachment to yourself and save the attachment).
2. Run `python src/email_analyzer.py path/to/message.eml --report reports/`.
3. Read `reports/<name>.md`. Search any attachment hash on VirusTotal **by hash only** - do not upload files that might contain personal data.

> Do not commit real emails to GitHub. They contain names, addresses and sometimes personal information.

## Project structure

```text
phishing-email-analyzer/
├── samples/            three safe sample emails (clean, credential phish, malicious attachment)
├── src/email_analyzer.py
├── tests/test_analyzer.py
└── requirements.txt    (standard library only)
```

## Ideas to extend it

- Look up attachment hashes with the VirusTotal API (free key)
- Parse `.msg` files with the `extract-msg` package
- Extract QR codes from images ("quishing")
- Output a STIX bundle of indicators

## Disclaimer

Sample emails are fictional and use reserved `.example` domains and RFC 5737 IP addresses. Attachments in the samples are harmless text with risky-looking names.
