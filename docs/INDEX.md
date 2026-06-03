# WIF Forensic — Complete Package Index

> **Corrupt Bitcoin Key Analyzer & Character Recovery**  
> *Offline-first forensic tool for validating, diagnosing, and recovering partially damaged Bitcoin WIF private keys.*

---

## 📦 Package Contents

```
wif-forensic/
├── wif_forensic.py          [954 lines] Main script (ready to run)
├── README.md                [720 lines] Full documentation & guide
├── CHANGELOG.md             Version history and release notes
├── SECURITY.md              [177 lines] Private key security guidance
├── LICENSE                  MIT License + disclaimer
├── .gitignore               Standard Python excludes
└── docs/
    ├── QUICKSTART.md        [179 lines] Get running in 2 minutes
    ├── INDEX.md             This file
    ├── HOW_IT_WORKS.md      [422 lines] Technical deep-dive
    └── GLOSSARY.md          [791 lines] Blockchain term reference
```

**Total:** ~3,240 lines of code + documentation

---

## 🚀 Quick Navigation

**First time?**
→ Start with **docs/QUICKSTART.md** (2-minute setup)

**Need security guidance?**
→ Read **SECURITY.md** (before entering any private key)

**Want full documentation?**
→ Read **README.md** (complete reference)

**Curious about the algorithms?**
→ Read **docs/HOW_IT_WORKS.md** (technical walkthrough)

**Need terminology help?**
→ Consult **docs/GLOSSARY.md** (searchable reference)

**Just run it:**
→ `python wif_forensic.py`

---

## 📄 File Descriptions

### `wif_forensic.py` — The Main Tool

**What it is:** A single-file Python 3 script that performs forensic analysis and recovery of Bitcoin WIF private keys.

**Lines of code:** 954

**Key sections:**
- Lines 1–60: Module docstring and overview
- Lines 61–100: Dependencies and constants
- Lines 101–210: Base58 encoding/decoding (from scratch, no libraries)
- Lines 211–240: Base58Check validation (with checksum verification)
- Lines 241–299: WIF key extraction and parsing
- Lines 300–330: secp256k1 public key derivation (via `ecdsa` library)
- Lines 331–378: Address generation (P2PKH, P2SH-P2WPKH, P2WPKH)
- Lines 379–430: Full analysis pipeline
- Lines 431–580: Multiprocessing worker and coordinator
- Lines 581–770: Output formatting and presentation
- Lines 771–880: Main entry point and user interaction
- Lines 881–955: Termux setup instructions

**Dependencies:**
- `ecdsa` — secp256k1 scalar multiplication
- `bech32` — native SegWit address encoding
- `hashlib`, `multiprocessing`, `itertools` (stdlib)

**Run time:** < 1 second for validation mode; 2–10 seconds for recovery mode (depending on number of unknowns)

---

### `README.md` — Full Documentation

**What it is:** Comprehensive guide covering:
1. Blockchain glossary for new testers
2. How Bitcoin keys work (full derivation chain)
3. What WIF Forensic does, step by step
4. Use cases (legitimate and not)
5. Installation on all platforms (Termux, Linux, macOS, Windows)
6. Usage with worked examples
7. How to read the output
8. Recovery mode and brute-force explanation
9. Multiprocessing design and determinism
10. Security constraints and limitations
11. Function reference
12. Troubleshooting

**Audience:** Anyone using this tool, from complete beginners to experienced developers.

**Key sections:**
- **Blockchain Glossary** — 40 terms with plain English + technical definitions
- **How Bitcoin Keys Work** — full cryptographic pipeline visualized
- **Use Cases** — 6 legitimate uses and 4 things the tool cannot do
- **Reading the Output** — field-by-field explanation of every output type
- **Recovery Mode Explained** — why exponential growth limits to 3 unknowns

---

### `docs/QUICKSTART.md` — 2-Minute Setup

**What it is:** Minimal, fast-track guide for experienced users.

**Covers:**
- One-liner installation per platform
- Three common usage scenarios
- Output interpretation (table format)
- Common mistakes and fixes

**Audience:** Users who know what WIF is and just want to get running.

**Size:** 179 lines — reads in 2–3 minutes.

---

### `SECURITY.md` — Private Key Security

**What it is:** Detailed guidance on handling Bitcoin private keys safely when using any tool, including this one.

**Covers:**
- The fundamental rule (private key = master secret)
- Pre-run steps (disconnect internet, check environment)
- Cloud sync risks (Screenshots, clipboard, notes apps)
- While-running do's and don'ts
- After-recovery best practices
- Common exposure mistakes
- Threat model (what this tool mitigates, what you must mitigate)

**Critical sections:**
- "Disconnect from the Internet" (with platform-specific steps)
- "Common Mistakes That Lead to Key Exposure" (table of 10 scenarios)
- "Trust and Open Source" (how to verify the code)

**Audience:** Everyone, especially first-time users and anyone recovering keys with real value.

---

### `docs/HOW_IT_WORKS.md` — Algorithm Deep-Dive

**What it is:** Line-by-line explanation of every algorithm in the tool.

**Covers:**
- Pre-validation (length, character set)
- Base58 decoding (step-by-step from bytes to integer back to bytes)
- Base58Check verification (double-SHA256 checksum)
- Key extraction (parsing version byte, raw key, compression flag)
- Public key derivation (secp256k1 scalar multiplication)
- Address generation (P2PKH, P2SH-P2WPKH, P2WPKH formulas)
- Recovery mode partitioning (determinism guarantee)
- Worker function design (pickle compatibility)
- Process context selection (fork vs. spawn)
- Full call graph

**Audience:** Developers, cryptography students, security researchers, or anyone who needs to verify the implementation.

**Key insights:**
- Why double-SHA-256 is used for checksums
- Why Base58 has exactly 58 characters
- Why the worker function is top-level (pickle limitation)
- Why Pool.map() preserves order (determinism)
- Why the 3-unknown cap is intentional (safety, not performance)

---

### `docs/GLOSSARY.md` — Blockchain Reference

**What it is:** Searchable reference of 80+ blockchain and Bitcoin technical terms.

**Organization:** Alphabetical (A–Z + Symbols)

**Coverage:**
- **Basic concepts:** Address, Bitcoin, Mainnet, Testnet, Private Key, Public Key
- **Encoding formats:** Base58, Base58Check, Bech32, WIF
- **Cryptography:** SHA-256, RIPEMD-160, HASH160, secp256k1, ECDSA, Elliptic Curve
- **Address types:** P2PKH, P2SH-P2WPKH, P2WPKH
- **Advanced:** SegWit, Witness, Scalar Multiplication, Discrete Logarithm
- **Technical:** Checksum, Compression Flag, Payload, Pickle, Multiprocessing, Fork/Spawn

**Each entry includes:**
- Plain English explanation
- Technical definition (where applicable)
- Why it matters
- Relevant formulas or examples

**Audience:** Anyone learning blockchain fundamentals, or needing quick technical reference.

---

### `LICENSE` — MIT + Disclaimer

**What it is:** Standard MIT License plus security-critical disclaimer.

**Key points:**
- Open source (MIT — permissive license)
- No warranty whatsoever
- Authors accept no liability for:
  - Funds lost due to misuse
  - Private key exposure on connected devices
  - Unauthorized use

**Audience:** Legal compliance, GitHub requirements.

---

### `.gitignore` — Standard Python Excludes

**What it is:** Standard `.gitignore` for Python projects.

**Excludes:**
- `__pycache__/`, `*.pyc`, `*.pyo`
- Virtual environments (`venv/`, `env/`, `.venv`)
- IDE settings (`.vscode/`, `.idea/`)
- Build artifacts (`dist/`, `build/`, `*.egg-info`)
- Test coverage, logs, OS files
- Any `.wif`, `.key`, `.pem` files (for safety)

---

## 🔑 Key Features by File

| Feature | File | Lines |
|---|---|---|
| **Tool (executable)** | `wif_forensic.py` | 954 |
| **Main documentation** | `README.md` | 720 |
| **Quick start** | `docs/QUICKSTART.md` | 179 |
| **Security guidance** | `SECURITY.md` | 177 |
| **Algorithm details** | `docs/HOW_IT_WORKS.md` | 422 |
| **Term reference** | `docs/GLOSSARY.md` | 791 |
| **Version history** | `CHANGELOG.md` | — |
| **License** | `LICENSE` | 30 |

---

## 🎯 Use Cases Covered

| Use Case | Read | Run |
|---|---|---|
| First time using | QUICKSTART → README | wif_forensic.py |
| Recovering 1–3 unknown chars | README (Recovery Mode) | wif_forensic.py with `?` |
| Understanding the algorithms | HOW_IT_WORKS | (reference, no run) |
| Learning blockchain terms | GLOSSARY | (reference, no run) |
| Securing private keys | SECURITY → README | (guidance, no run) |
| Verifying a complete WIF | QUICKSTART | wif_forensic.py |
| Debugging tool output | README (Reading the Output) | wif_forensic.py |
| Contributing to the project | HOW_IT_WORKS | review wif_forensic.py |

---

## 📊 Documentation Statistics

| Document | Lines | Words | Reading Time |
|---|---|---|---|
| QUICKSTART.md | 179 | 1,100 | 2–3 min |
| README.md | 720 | 5,500 | 12–15 min |
| SECURITY.md | 177 | 1,700 | 4–5 min |
| HOW_IT_WORKS.md | 422 | 3,200 | 8–10 min |
| GLOSSARY.md | 791 | 4,000 | 10–12 min |
| **Total Documentation** | **2,289** | **15,500** | **36–45 min** |
| **Plus Code** | **954** | — | — |
| **Grand Total** | **3,243** | — | — |

---

## 🔒 Security Mentions Across Docs

Every document mentions private key security:

| Document | Security Coverage |
|---|---|
| README.md | Entire section + glossary definitions + warnings |
| QUICKSTART.md | Header warning + post-recovery steps |
| SECURITY.md | 100% focused (7 major sections) |
| wif_forensic.py | Banner warning + inline comments |
| GLOSSARY.md | "Private Key" entry + cross-references |
| HOW_IT_WORKS.md | One-way function security rationale |

**Total security guidance:** ~2,000 words across the package

---

## 🚀 How to Get Started

### Step 1: Read docs/QUICKSTART.md (2 min)
Understand what you're installing and how to run it.

### Step 2: Read SECURITY.md (4 min)
**Mandatory before entering any real private key.** Understand the risks and mitigations.

### Step 3: Install (1 min)
```bash
pip install ecdsa bech32
python wif_forensic.py
```

### Step 4: Run & Test (2 min)
Use a test WIF or the example from QUICKSTART to verify it works.

### Step 5: Use on Real Keys (as needed)
If recovering an actual private key:
1. Run on offline device
2. Verify recovered addresses against known source
3. Import to cold storage immediately
4. Sweep funds to fresh address

---

## 📖 Advanced Navigation

**By audience:**
- **Beginner:** QUICKSTART → README → GLOSSARY as needed
- **Developer:** HOW_IT_WORKS → review wif_forensic.py source
- **Security-conscious:** SECURITY → README (Security Constraints section)
- **Educator:** README (full glossary) + HOW_IT_WORKS
- **Contributor:** HOW_IT_WORKS → source code review → docs

**By topic:**
- **Bitcoin basics:** README (Blockchain Glossary) + GLOSSARY.md
- **How addresses are made:** HOW_IT_WORKS (Stage 6) + GLOSSARY (P2PKH/P2SH-P2WPKH/P2WPKH entries)
- **Why checksums matter:** README (Why Checksum Matters) + HOW_IT_WORKS (Stage 3)
- **Why brute-force is limited:** README (Recovery Mode & Brute-Force Explained) + HOW_IT_WORKS (Why 3-Unknown Cap)
- **Multiprocessing details:** HOW_IT_WORKS (Stage 7)
- **Security best practices:** SECURITY.md + README (Security Constraints)

---

## 💡 Key Concepts by Document

| Concept | Introduced in | Deep dive in |
|---|---|---|
| WIF (Wallet Import Format) | QUICKSTART | README + HOW_IT_WORKS |
| Base58Check | README Glossary | HOW_IT_WORKS Stage 3 |
| Checksum | README Glossary | HOW_IT_WORKS Stage 3 |
| secp256k1 | README Glossary | HOW_IT_WORKS Stage 5 |
| Address Types (3 formats) | README Glossary | HOW_IT_WORKS Stage 6 |
| Compression Flag | README Glossary | HOW_IT_WORKS Stage 4 |
| Multiprocessing | HOW_IT_WORKS Stage 7 | wif_forensic.py lines 431–580 |
| Determinism | README (Multiprocessing) | HOW_IT_WORKS (Partitioning) |
| Private key security | SECURITY.md | README (Security Constraints) |

---

## ✅ Verification Checklist

Before using this tool on a real private key:

- [ ] I have read SECURITY.md
- [ ] I have disconnected from the Internet
- [ ] I understand that a private key is the master secret and cannot be recovered if lost
- [ ] I understand that anyone with the private key can steal all associated funds
- [ ] I will not screenshot, paste, email, or share the recovered key with anyone
- [ ] I will verify the recovered addresses against a trusted source
- [ ] I will import the recovered key to cold storage immediately
- [ ] I have read the code (or trust the source) — it makes no network calls

---

## 📞 Support

**If something doesn't work:**
1. Check docs/QUICKSTART.md (common mistakes)
2. Check README.md troubleshooting section
3. Review SECURITY.md to verify your environment is correct
4. Read the inline comments in wif_forensic.py
5. Verify your Python and library versions are correct

**If you want to contribute:**
1. Read HOW_IT_WORKS.md to understand the algorithms
2. Review the wif_forensic.py source
3. Ensure any changes preserve determinism and offline-first design

---

## 📜 License & Disclaimer

MIT License — see LICENSE file for full text.

**Key point:** This software is provided AS-IS for educational and personal wallet recovery purposes. The authors accept no liability for misuse, exposure of keys on connected devices, or funds lost.

---

## 🔗 Related Resources

**Bitcoin & Cryptography:**
- Bitcoin Whitepaper: https://bitcoin.org/bitcoin.pdf
- secp256k1 Specification: https://en.wikipedia.org/wiki/Secp256k1
- FIPS 186-4 (ECDSA): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

**Bitcoin Standards (BIPs):**
- BIP 141 (SegWit): https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- BIP 173 (Bech32): https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

**Hardware Wallets (cold storage):**
- Ledger: https://www.ledger.com/
- Trezor: https://trezor.io/
- Coldcard: https://coldcard.com/

---

**Last updated:** June 2025  
**Version:** 2.0 (multiprocessing + full documentation)  
**Status:** Production-ready for wallet recovery
