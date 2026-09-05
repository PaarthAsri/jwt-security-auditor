# JWT Audit

A Python CLI tool for auditing **JSON Web Tokens (JWTs)** for common security issues and configuration weaknesses.

JWT Audit analyzes a token's structure, headers, claims, and signing configuration, then produces security findings with evidence, severity, explanation, and remediation guidance.

It is designed primarily for **penetration testing, application security testing, security labs, and CI security checks**.

**Built by Paarth Asri**

\---

## Table of Contents

* [What It Checks](#what-it-checks)
* [JWT Structure](#jwt-structure)
* [Algorithm \& Header Security](#algorithm--header-security)
* [Claim Analysis](#claim-analysis)
* [Sensitive Data Exposure](#sensitive-data-exposure)
* [HMAC Secret Testing](#hmac-secret-testing)
* [Risk Scoring](#risk-scoring)
* [Output Formats](#output-formats)
* [CI Security Gating](#ci-security-gating)
* [Installation](#installation)
* [Usage](#usage)
* [Project Structure](#project-structure)
* [Main Components](#main-components)
* [Testing](#testing)
* [Limitations](#limitations)
* [Responsible Use](#responsible-use)
* [Why I Built This](#why-i-built-this)
* [Author](#author)

\---

## What It Checks

### JWT Structure

JWT Audit safely analyzes the basic structure of a JWT and:

* Decodes the JWT header and payload
* Validates JWT structure and Base64URL encoding
* Handles malformed tokens without crashing
* Reports structural problems as security findings
* Calculates token age and lifetime where the required claims are available

\---

### Algorithm \& Header Security

Checks for potentially unsafe JWT configurations, including:

* `alg: none`
* Missing or unexpected `alg`
* Non-standard algorithm values
* `jku`, `x5u`, and embedded `jwk` key sources
* Suspicious `kid` values, including path traversal and injection-style patterns
* `crit` header extensions
* Potential algorithm/key-type confusion

The tool reports these as **security indicators**. Static JWT analysis alone does not prove that a server is exploitable; server-side behavior must be validated separately.

\---

### Claim Analysis

JWT Audit checks standard JWT claims including:

|Claim|Purpose|
|-|-|
|`exp`|Expiration time|
|`nbf`|Not-before time|
|`iat`|Issued-at time|
|`iss`|Token issuer|
|`aud`|Intended audience|
|`sub`|Token subject|

It identifies issues such as:

* Missing expiration
* Invalid claim types
* Expired tokens
* Tokens that are not yet valid
* Invalid timestamps
* Excessively long token lifetimes
* Missing `iss`, `aud`, or `sub` claims where applicable

\---

### Sensitive Data Exposure

JWT payloads are **encoded, not encrypted**, so their contents can be read by anyone who has the token.

JWT Audit checks payloads for potentially sensitive information such as:

* Passwords
* Secrets
* API keys
* Personal information
* Payment-card-shaped values

These checks are intended to highlight potential sensitive-data exposure and should be reviewed in the context of the target application.

\---

### HMAC Secret Testing

For `HS256`, `HS384`, and `HS512` tokens, JWT Audit can optionally perform an **offline dictionary check** against a user-provided wordlist.

```bash
jwt-audit \\\\
  --file token.txt \\\\
  --check-secret \\\\
  --wordlist my-authorized-wordlist.txt \\\\
  --i-am-authorized
```

The check:

* Runs completely offline
* Only tests candidates supplied through the wordlist
* Does not generate candidates
* Does not perform network requests
* Requires an explicit authorization flag
* Has a configurable candidate limit

This functionality is intended for tokens and systems you are authorized to assess.

\---

## Risk Scoring

Each finding receives a severity level and contributes to an overall **0–100 risk score**.

Reports include:

* Overall risk score
* Highest finding severity
* Finding title
* Evidence
* Explanation
* Remediation
* Security classification information where available

The goal is to make the output useful for both **manual security testing and automated security workflows**.

\---

## Output Formats

JWT Audit supports three report formats:

### Text

Human-readable output directly in the terminal:

```bash
jwt-audit --token "eyJhbGciOi..."
```

### JSON

Useful for automation, scripting, and CI pipelines:

```bash
jwt-audit \\\\
  --file token.txt \\\\
  --format json \\\\
  --output result.json
```

### HTML

Generates a self-contained HTML security report:

```bash
jwt-audit \\\\
  --file token.txt \\\\
  --format html \\\\
  --output report.html
```

\---

## CI Security Gating

JWT Audit provides exit codes based on finding severity, allowing it to be integrated into security pipelines.

```bash
jwt-audit --file token.txt --fail-on CRITICAL
```

### Exit Codes

|Code|Meaning|
|-:|-|
|`0`|Highest finding severity is below the selected `--fail-on` severity|
|`1`|Highest finding meets `--fail-on` but is below CRITICAL|
|`2`|Highest finding is CRITICAL|
|`3`|Usage or execution error|

\---

## Installation

JWT Audit currently uses only the **Python standard library** and requires **Python 3.10+**.

Clone the repository:

```bash
git clone https://github.com/paarthasri/jwt-security-auditor.git
cd jwt-security-auditor
```

Run the test suite:

```bash
python3 -m unittest discover -s tests -p "test\\\_\\\*.py"
```

Run the CLI directly:

```bash
python3 -m jwt\\\_audit --token "<JWT>"
```

If the package is configured with a CLI entry point, it can also be run as:

```bash
jwt-audit --token "<JWT>"
```

\---

## Usage

### Audit a JWT

```bash
jwt-audit --token "eyJhbGciOi..."
```

### Read a token from a file

The file parser accepts common formats such as:

```text
Authorization: Bearer eyJ...
```

Run:

```bash
jwt-audit --file token.txt
```

### Generate JSON output

```bash
jwt-audit \\\\
  --file token.txt \\\\
  --format json \\\\
  --output result.json
```

### Generate an HTML report

```bash
jwt-audit \\\\
  --file token.txt \\\\
  --format html \\\\
  --output report.html
```

### Test an HMAC signing secret

For authorized testing only:

```bash
jwt-audit \\\\
  --file token.txt \\\\
  --check-secret \\\\
  --wordlist my-authorized-wordlist.txt \\\\
  --i-am-authorized
```

\---

## Project Structure

```text
jwt-security-auditor/
│
├── jwt\\\_audit/
│   ├── decoder.py
│   ├── analyzer.py
│   ├── secret\\\_check.py
│   ├── report.py
│   └── cli.py
│
├── tests/
│   ├── token\\\_factory.py
│   ├── test\\\_decoder.py
│   ├── test\\\_analyzer.py
│   └── test\\\_secret\\\_check.py
│
├── requirements.txt
├── README.md
└── ...
```

\---

## Main Components

### `decoder.py`

Handles:

* JWT parsing
* Header and payload decoding
* Base64URL processing
* Structural validation

### `analyzer.py`

Runs the security checks and generates:

* Finding objects
* Severity ratings
* Security evidence
* Risk scores

### `secret\\\_check.py`

Performs the optional offline HMAC dictionary check against `HS256`, `HS384`, and `HS512` tokens.

### `report.py`

Generates:

* Text reports
* JSON reports
* HTML reports

### `cli.py`

Provides:

* Command-line interface
* Argument handling
* Input processing
* Report selection
* CI exit codes

\---

## Testing

The project includes deliberately crafted JWT test cases covering different security conditions and malformed inputs.

Run the complete test suite with:

```bash
python3 -m unittest discover -s tests -p "test\\\_\\\*.py"
```

The test suite covers areas including:

* JWT decoding
* Malformed tokens
* Header analysis
* Claim validation
* Expiration and token lifetime checks
* Security findings
* HMAC secret checking

\---

## Limitations

JWT Audit is primarily a **static JWT analysis tool**.

It does not:

* Contact the token issuer
* Make requests to a target application
* Automatically confirm server-side authorization bypasses
* Automatically exploit JWT vulnerabilities
* Forge tokens for use against third-party systems
* Replace manual application security testing

For example, detecting `alg: none` indicates that an unsigned algorithm is present in the token. It **does not by itself prove that the target application accepts unsigned tokens**.

Server-side behavior should be tested separately in an authorized environment.

\---

## Responsible Use

Use JWT Audit only with tokens and applications you are authorized to test, such as:

* Your own applications
* Local security labs
* CTF environments
* Authorized penetration tests
* Systems covered by a bug bounty or security testing program

> \\\*\\\*Do not use the tool to test tokens or applications without permission.\\\*\\\*

The author is not responsible for misuse of this tool.

\---

## Why I Built This

I built JWT Audit as a compact security tool to deepen my understanding of:

* JWT authentication
* Token validation
* Application security
* Web application vulnerabilities
* Penetration-testing workflows
* Security automation

The project focuses on turning common JWT security checks into a **repeatable CLI workflow** rather than simply decoding tokens.

\---

## Author

### Paarth Asri

Cybersecurity | Application Security | Security Research

[GitHub](https://github.com/paarthasri) • [LinkedIn](https://linkedin.com/in/paarth-asri)

\---

## Disclaimer

JWT Audit is intended for **educational purposes, security research, and authorized security testing**.

Always obtain appropriate permission before testing systems, applications, or tokens that you do not own.

