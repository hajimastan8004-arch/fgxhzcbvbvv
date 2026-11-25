# TokenSpy — JWT Security Analyzer

TokenSpy is a command-line tool, written in pure Python, that decodes JSON
Web Tokens (JWTs), checks their signing algorithm, verifies HMAC
signatures, probes for the classic `alg: none` bypass against your own
lab application, searches for weak HMAC secrets with a wordlist, audits
the standard claims (`exp`, `iat`, `nbf`, `iss`, `aud`) for common
mistakes, and produces a findings report with severities and remediation
advice.

It was built as a learning project: **no JWT library is used anywhere**.
Base64URL decoding and HMAC signature verification are implemented from
scratch with Python's standard-library `hmac` and `hashlib` modules, so
the project demonstrates an actual understanding of how JWT
authentication can fail — not just how to call a library that does it
for you.

> ⚠️ **Ethical use only.** TokenSpy's active tests (the `alg:none` probe
> and the weak-secret search) are for tokens, secrets, and verification
> endpoints that belong to **you**, in an isolated lab. See
> [Security Limitations & Ethical Usage](#security-limitations--ethical-usage-disclaimer)
> below.

---

## Features

| # | Feature | Module |
|---|---------|--------|
| 1 | JWT decoding (manual Base64URL + JSON) | `decoder.py`, `utils.py` |
| 2 | Algorithm detection (`alg: none` → CRITICAL, unsupported/asymmetric → flagged) | `algorithm_check.py` |
| 3 | HMAC signature verification (HS256/384/512, constant-time compare) | `signature.py` |
| 4 | `alg: none` acceptance test against **your own** lab endpoint | `vulnerability_tests.py` |
| 5 | Weak-secret detection via wordlist (local only, no network) | `vulnerability_tests.py` |
| 6 | Claims security analysis (`exp`, `iat`, `nbf`, `iss`, `aud`, sensitive data) | `claims_analyzer.py` |
| + | `kid` header inspection (path-traversal / injection patterns) | `algorithm_check.py` |
| + | Batch analysis of multiple tokens + summary table | `main.py`, `report_generator.py` |
| + | Text + JSON report export, secrets always redacted | `report_generator.py` |

## Project Structure

```
TokenSpy/
├── main.py                  # CLI entry point: banner, menu, argparse commands
├── decoder.py                # Feature 1: JWT decoding
├── signature.py               # Feature 3: HMAC signature verification
├── algorithm_check.py         # Feature 2 (+ kid inspection)
├── claims_analyzer.py         # Feature 6: claims analysis
├── vulnerability_tests.py     # Features 4 & 5: alg:none test, weak-secret search
├── report_generator.py        # Feature 7: report building, text/JSON export
├── utils.py                   # Base64URL, colors, redaction, helpers
├── wordlists/
│   └── weak_secrets.txt       # Sample weak-secret wordlist
├── samples/
│   └── sample_tokens.txt      # 10 lab tokens covering every test scenario
├── reports/                    # Generated reports land here
├── tests/
│   ├── test_tokenspy.py       # Automated test suite (18 tests)
│   ├── token_factory.py       # Mints the 10 scenario tokens for testing
│   └── lab_app.py             # Tiny Flask app to test Feature 4 against
├── requirements.txt
└── README.md
```

## Installation

```bash
git clone <your-repo-url> TokenSpy
cd TokenSpy
pip install -r requirements.txt
```

TokenSpy needs **no third-party packages** for decoding, verification,
claims analysis, weak-secret search, or reporting. `requests` is only
imported when you run the `alg:none` endpoint test, and `flask` is only
needed if you want to run the included lab app.

## Usage

### Interactive menu

```bash
python main.py
# or
python main.py menu
```

```
TOKENSPY — JWT SECURITY ANALYZER  (v1.0.0)
Decode • Verify • Attack-test (lab-only) • Report

[1] Decode JWT
[2] Analyze JWT Security
[3] Verify Signature
[4] Test Algorithm None
[5] Detect Weak Secrets
[6] Analyze Claims
[7] Generate Security Report
[8] Exit
```

### Command line

Decode + fully analyze one token:

```bash
python main.py analyze --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...." \
  --secret "my-lab-secret" \
  --wordlist wordlists/weak_secrets.txt \
  --report-name reports/tokenspy_report
```

From a file instead of inline:

```bash
python main.py analyze --file samples/sample_tokens.txt --secret "my-lab-secret"
```

Run the `alg:none` acceptance test against **your own** lab endpoint:

```bash
python main.py analyze --token "<token>" --test-alg-none \
  --endpoint http://127.0.0.1:5000/verify
```

Batch mode (one token per line):

```bash
python main.py batch --batch samples/sample_tokens.txt \
  --wordlist wordlists/weak_secrets.txt --report-name reports/batch_run
```

### Sample output

```
-- Algorithm --  CRITICAL  alg is set to 'none'. This token claims to
require no signature at all. If any verifier accepts this,
authentication is completely bypassable.

-- alg:none Endpoint Test --  Lab endpoint responded with HTTP 200. The
unsigned ('alg: none') token was ACCEPTED.

OVERALL ASSESSMENT: CRITICAL
```

## Creating Test JWTs

`tests/token_factory.py` mints lab-only JWTs for every required test
scenario (correct token, wrong secret, tampered payload, `alg: none`,
missing/expired `exp`, weak secret, strong secret, missing `iss`/`aud`,
and a fully clean token). Regenerate `samples/sample_tokens.txt` any time
with:

```bash
python -c "
from tests.token_factory import scenario_tokens
with open('samples/sample_tokens.txt', 'w') as f:
    for name, tok in scenario_tokens().items():
        f.write(f'# {name}\n{tok}\n')
"
```

To test **Feature 4** live, the repo includes a tiny Flask lab app
(`tests/lab_app.py`) that mints and verifies its own HS256 tokens — a
safe, authorized target that is entirely separate from TokenSpy's own
code:

```bash
# Terminal 1 — secure mode (correctly rejects alg:none)
python tests/lab_app.py

# Terminal 2 — mint a token and point TokenSpy at it
python tests/lab_app.py --mint
python main.py analyze --token "<token from above>" \
  --test-alg-none --endpoint http://127.0.0.1:5000/verify
# -> reports REJECTED

# To see the CRITICAL finding fire, restart the lab app in vulnerable mode:
python tests/lab_app.py --vulnerable
# -> TokenSpy now reports ACCEPTED / CRITICAL
```

## Running Tests

```bash
python -m unittest tests.test_tokenspy -v
# or, if pytest is installed:
python -m pytest tests/ -v
```

The suite covers all 10 required scenarios: a correct token with a valid
secret, verification against an incorrect secret, a tampered payload, an
`alg: none` token, missing expiry, an expired token, a weak secret found
via wordlist, a strong secret correctly *not* found, missing `iss`/`aud`,
and a fully clean token. The `alg:none` HTTP probe is tested with the
network layer mocked — the automated suite never makes a real network
call; the live endpoint test only runs when a human explicitly supplies
`--endpoint` on the command line.

## Security Limitations

- TokenSpy only verifies **HMAC** signatures (HS256/384/512). Tokens
  signed with RSA/ECDSA (RS256, ES256, etc.) are flagged but their
  signatures are not cryptographically checked.
- The weak-secret search is only as good as the wordlist you provide; it
  is a demonstration of the technique, not an exhaustive cracking tool.
- The `alg:none` test uses a simple heuristic (HTTP 2xx = accepted); a
  real target's API contract may need a different success check.
- This is an educational project, not a production-grade security
  scanner. Do not rely on it as your only line of defense.

## Ethical Usage Disclaimer

TokenSpy is built strictly for **learning and for testing systems you
own or are explicitly authorized to test**, inside an isolated lab
environment:

- The `alg:none` endpoint test (Feature 4) **only ever contacts an
  endpoint you explicitly pass with `--endpoint`**. There is no default
  or hidden target, and the tool never guesses one.
- The weak-secret search (Feature 5) does not touch the network at all —
  it only recomputes signatures locally against tokens and a wordlist
  you supply.
- Never run TokenSpy's active tests against a system you do not own or
  do not have written permission to test. Unauthorized access to a
  computer system is a criminal offense in most jurisdictions.

This tool was built for the *"Build Your Own Security Tool"* assignment
(PNY Trainings, Cyber Security Department, instructor Abdul Mannan), and
every test scenario and sample token in this repository was minted
locally for that lab — none of it touches a real service or real
credentials.
