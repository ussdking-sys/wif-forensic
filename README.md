# WIF Forensic — *Corrupt Bitcoin Key Analyzer & Character Recovery*

> **Offline-first forensic tool for validating, diagnosing, and recovering partially damaged Bitcoin WIF private keys. Built for wallet recovery analysis, security research, and blockchain education.**

---

> ## 🔴 CRITICAL SECURITY WARNING — READ BEFORE USING
>
> **A Bitcoin private key is the master password to your funds. Anyone who sees it can steal everything in the associated wallet — instantly and irreversibly.**
>
> - **Run this tool on a device with no internet connection.** Disable Wi-Fi and mobile data before launching.
> - **Never paste a real private key into any online tool, website, chat, or forum** — not even to ask for help. Not even here.
> - **Never share your WIF string with another person, screenshot it, or copy it to your clipboard on a connected device.**
> - **Do not run this script in a cloud shell, Replit, Google Colab, or any remote environment** — those environments log your input.
> - **After recovery, move your recovered WIF string directly to a hardware wallet or cold storage.** Do not store it in a notes app, cloud drive, or email.
> - This tool writes **nothing to disk** and makes **zero network calls**. You can verify this by reading the source.

---

## What Is This?

WIF Forensic is a Python 3 command-line tool that performs **forensic analysis** of Bitcoin private keys in WIF format. It can:

- **Validate** a WIF string and explain exactly why it passes or fails
- **Diagnose** corruption: wrong length, illegal characters, checksum mismatch
- **Recover** keys with up to 3 unknown or corrupted characters by trying all possible values in parallel
- **Derive** the full set of Bitcoin addresses (Legacy, SegWit-wrapped, Native SegWit) from any valid key

It is designed to run on **Android via Termux** with no internet access, making it suitable for air-gapped recovery workflows.

---

## Table of Contents

1. [Blockchain Glossary for New Testers](#-blockchain-glossary-for-new-testers)
2. [How Bitcoin Keys Work — The Full Chain](#-how-bitcoin-keys-work--the-full-chain)
3. [What WIF Forensic Does, Step by Step](#-what-wif-forensic-does-step-by-step)
4. [Use Cases](#-use-cases)
5. [Installation](#-installation)
6. [Usage & Examples](#-usage--examples)
7. [Reading the Output](#-reading-the-output)
8. [Recovery Mode & Brute-Force Explained](#-recovery-mode--brute-force-explained)
9. [Multiprocessing Design](#-multiprocessing-design)
10. [Security Constraints & What This Tool Won't Do](#-security-constraints--what-this-tool-wont-do)
11. [Function Reference](#-function-reference)
12. [Troubleshooting](#-troubleshooting)

---

## 📖 Blockchain Glossary for New Testers

This section explains the terms you will encounter — both in common usage and technically. If you already know Bitcoin cryptography, skip to [How Bitcoin Keys Work](#-how-bitcoin-keys-work--the-full-chain).

---

### Private Key

**Plain English:** The master secret that proves you own a Bitcoin wallet. Like the PIN to a bank account — except there is no bank, no reset button, and no customer service.

**Technical:** A random 256-bit integer (32 bytes) chosen from the range `[1, n-1]` where `n` is the order of the secp256k1 elliptic curve. In hex it looks like:

```
0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
```

If you lose it, your funds are gone. If anyone else sees it, your funds are gone.

---

### Public Key

**Plain English:** A value derived from the private key that can be shared freely. It proves you *could* produce the private key without revealing it.

**Technical:** The result of elliptic curve scalar multiplication: `PublicKey = PrivateKey × G`, where `G` is the secp256k1 generator point. The compressed form is 33 bytes (a parity prefix byte `0x02` or `0x03`, plus the 32-byte X coordinate of the curve point). It cannot be reversed to find the private key — that would require solving the elliptic curve discrete logarithm problem, which is computationally infeasible.

---

### Bitcoin Address

**Plain English:** What you share with someone who wants to send you Bitcoin. Like a bank account number, but derived mathematically from your public key.

**Technical:** A shortened, encoded hash of the public key. Three formats exist:

| Format | Starts With | Algorithm |
|---|---|---|
| **P2PKH** — Legacy | `1` | Base58Check( `0x00` ‖ HASH160(pubkey) ) |
| **P2SH-P2WPKH** — SegWit wrapped | `3` | Base58Check( `0x05` ‖ HASH160(redeemScript) ) |
| **P2WPKH** — Native SegWit | `bc1q` | Bech32( HASH160(pubkey) ) |

All three formats can be derived from the same private key. You can receive Bitcoin on any of them.

---

### WIF — Wallet Import Format

**Plain English:** A standardised way to write down and transfer a Bitcoin private key. Instead of a long hex number, it uses a shorter string of letters and numbers that includes a built-in error-detection code.

**Technical:** A Base58Check encoding of `[version byte] + [32-byte private key] + [optional 0x01 compression flag]`. The version byte is `0x80` for mainnet and `0xEF` for testnet. The last 4 bytes of the final encoded data are a checksum (first 4 bytes of `SHA256(SHA256(payload))`).

A compressed mainnet WIF is always **52 characters** and starts with `K` or `L`.
An uncompressed mainnet WIF is always **51 characters** and starts with `5`.

---

### Base58

**Plain English:** A way of writing binary data as readable text, using 58 characters instead of the full alphabet. The 4 excluded characters — `0` (zero), `O` (capital O), `I` (capital I), and `l` (lowercase L) — are removed specifically because they look too similar to each other in most fonts, which would cause transcription errors.

**Technical:** A positional numeral system with base 58. Each character represents a digit in the alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`. The binary data is treated as a big-endian integer, divided repeatedly by 58, and the remainders are used as character indices. Leading zero bytes are preserved as leading `1` characters.

---

### Base58Check

**Plain English:** Base58, but with a checksum appended so you can detect typos.

**Technical:** The payload is hashed twice with SHA-256 (`SHA256(SHA256(payload))`), the first 4 bytes of the result are appended to the payload, and then the whole thing is Base58-encoded. On decode, the same process is run and the embedded checksum is compared to the recomputed one. A mismatch means the string is corrupt or wrong.

---

### Checksum

**Plain English:** A short fingerprint derived from data. If the data changes even slightly, the fingerprint changes too — letting you detect corruption or typos.

**Technical:** In Bitcoin's Base58Check encoding, the checksum is 4 bytes (32 bits). It is the first 4 bytes of `SHA256(SHA256(payload))`. The probability of a random string accidentally passing checksum validation is `1/2^32` ≈ 1 in 4.3 billion.

---

### SHA-256

**Plain English:** A mathematical blender. Pour in any data, get out a fixed 32-byte "fingerprint." Change even one bit of input and the output is completely different. You cannot reverse it.

**Technical:** SHA-256 (Secure Hash Algorithm 256-bit) is a one-way cryptographic hash function from the SHA-2 family. Bitcoin uses it doubled (`SHA256d`) for checksums and transaction hashing. It is standardised in FIPS 180-4.

---

### RIPEMD-160

**Plain English:** Another one-way fingerprinting function, but it produces a shorter 20-byte output. Bitcoin uses it after SHA-256 to shorten public keys for addresses.

**Technical:** RACE Integrity Primitives Evaluation Message Digest (160-bit). The combination `RIPEMD160(SHA256(data))` — called `HASH160` in Bitcoin — produces the 20-byte hash that forms the core of a Bitcoin address. The double-hash approach is used for belt-and-suspenders security in case one algorithm is weakened.

---

### secp256k1

**Plain English:** The specific mathematical curve that Bitcoin uses for its key pair system. It defines how private keys map to public keys.

**Technical:** An elliptic curve over the prime field `Fp` where `p = 2^256 - 2^32 - 977`. Its parameters were chosen for efficiency and verifiably pseudo-random properties. The curve equation is `y² = x³ + 7`. Key operations: scalar multiplication (private → public key), and ECDSA signing/verification (proving ownership of a private key without revealing it).

---

### Mainnet vs Testnet

**Plain English:** Mainnet is the real Bitcoin network where coins have real value. Testnet is a practice network where coins are worthless — used for testing software.

**Technical:** Distinguished by the version byte in WIF encoding:
- Mainnet: version byte `0x80` → WIF starts with `5`, `K`, or `L`
- Testnet: version byte `0xEF` → WIF starts with `9` or `c`

This tool detects and reports which network a key belongs to.

---

### Compressed vs Uncompressed Key

**Plain English:** Two ways to write a public key. Compressed is smaller and modern; uncompressed is older and larger. The choice affects which Bitcoin address is generated from a given private key.

**Technical:** An uncompressed public key is 65 bytes (`0x04` ‖ X ‖ Y). A compressed key is 33 bytes (`0x02` or `0x03` ‖ X), where the prefix encodes the parity of Y. WIF encodes the compression preference with an optional trailing `0x01` byte in the payload. A compressed WIF is 52 chars; uncompressed is 51.

---

### Elliptic Curve / ECDSA

**Plain English:** The mathematical system that makes Bitcoin signatures work. It lets you prove you own a private key without ever showing it.

**Technical:** ECDSA (Elliptic Curve Digital Signature Algorithm) on secp256k1. A signature is a pair `(r, s)` computed from the private key and a message hash. Verification uses only the public key, the message hash, and the signature — the private key is never revealed. The security relies on the infeasibility of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

---

### Bech32

**Plain English:** A newer, more error-resistant encoding used for native SegWit addresses (the `bc1q...` ones).

**Technical:** A human-readable encoding scheme defined in BIP-0173. Uses a 32-character alphabet (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`) and a BCH (Bose–Chaudhuri–Hocquenghem) checksum that can detect — and in some cases correct — up to 4 errors. Human-readable part (HRP) is `bc` for mainnet, `tb` for testnet.

---

### SegWit (Segregated Witness)

**Plain English:** A 2017 Bitcoin upgrade that moved signature data out of the main transaction body, reducing transaction sizes and fees.

**Technical:** Defined in BIP-0141. Introduces new script types: P2WPKH (pay to witness public key hash) and P2WSH (pay to witness script hash). SegWit transactions have a lower "weight" than legacy transactions, resulting in lower fees for the same byte count. Native SegWit addresses start with `bc1q`; wrapped SegWit (P2SH-P2WPKH) starts with `3`.

---

## 🔗 How Bitcoin Keys Work — The Full Chain

Understanding the derivation pipeline helps you understand what WIF Forensic is actually doing at each step.

```
Random 256-bit integer
        │
        ▼
  Private Key (32 bytes, hex)
        │
        │  × G  (secp256k1 scalar multiplication)
        ▼
  Public Key
  ├── Uncompressed (65 bytes): 04 ‖ X ‖ Y
  └── Compressed   (33 bytes): 02/03 ‖ X
        │
        │  HASH160 = RIPEMD160(SHA256(pubkey))
        ▼
  Public Key Hash (20 bytes)
        │
        ├──────────────────────────────────────────┐
        │                                          │
        ▼                                          ▼
  P2PKH address                           redeemScript = OP_0 ‖ hash
  Base58Check(0x00 ‖ hash)               HASH160(redeemScript)
  → starts with "1"                       Base58Check(0x05 ‖ scriptHash)
                                          → starts with "3"

                                          Also: Bech32(hash, witness_v0)
                                          → starts with "bc1q"
```

The **WIF encoding** of the private key is a separate branch:

```
Private Key (32 bytes)
        │
        │  Prepend version byte (0x80 mainnet / 0xEF testnet)
        │  [Optional: append 0x01 for compressed]
        ▼
  Versioned Payload (33 or 34 bytes)
        │
        │  Checksum = SHA256(SHA256(payload))[0:4]
        │  Append checksum
        ▼
  Payload + Checksum (37 or 38 bytes)
        │
        │  Base58 encode
        ▼
  WIF String (51 or 52 characters)
```

WIF Forensic reverses this entire pipeline for any given WIF string.

---

## 🔬 What WIF Forensic Does, Step by Step

### Mode 1 — Validation (no `?` characters)

1. **Pre-validation** — check length (51 or 52 chars) and character set (Base58 alphabet only)
2. **Base58 decode** — convert the string back to raw bytes
3. **Checksum split** — separate the last 4 bytes (embedded checksum) from the payload
4. **Checksum recompute** — run `SHA256(SHA256(payload))` and take the first 4 bytes
5. **Compare** — if embedded == computed, the key is valid; if not, report the mismatch in hex
6. **Key extraction** — parse version byte, 32-byte raw key, compression flag
7. **Public key derivation** — compute `PrivKey × G` on secp256k1 via the `ecdsa` library
8. **Address generation** — derive all three address formats from the compressed public key

### Mode 2 — Recovery (template contains `?` characters)

All of the above, but repeated for every possible candidate produced by substituting Base58 characters into the `?` positions. Only candidates that pass full checksum validation are returned. Runs in parallel across all CPU cores.

---

## 🎯 Use Cases

### ✅ Legitimate Uses

| Scenario | How to use this tool |
|---|---|
| You wrote down a WIF key and one character is smudged or unreadable | Mark it with `?` and run recovery mode |
| You have a WIF from an old backup and want to verify it before importing to a wallet | Run validation mode — check the checksum and derive addresses |
| You're building a wallet application and need to understand the WIF encoding spec | Read the source — every step is commented and explained |
| You're teaching blockchain fundamentals and need a concrete worked example | Use `--` prefixed test keys from Bitcoin's documentation |
| You're a QA tester verifying that your wallet software rejects malformed WIF input | Generate invalid inputs and observe the diagnostic output |
| You found a partial key in a old encrypted note and need to attempt recovery | Use recovery mode with `?` placeholders for the missing characters |

### ❌ What This Tool Cannot Do

- It cannot recover a key with **more than 3 unknown characters** (the search space is too large)
- It cannot recover a key where you have **no partial information** — that requires brute-forcing a 256-bit space, which is impossible
- It cannot interact with the Bitcoin network in any way
- It cannot sign transactions, broadcast anything, or move funds
- It cannot crack encryption on password-protected wallets (BIP-38)

---

## 💻 Installation

### On Android (Termux) — Primary Target

```bash
# Step 1: Install Termux from F-Droid (NOT the Play Store version — it's outdated)
# https://f-droid.org/en/packages/com.termux/

# Step 2: Update packages and install Python + OpenSSL
pkg update && pkg upgrade
pkg install python openssl

# Step 3: Install Python dependencies
pip install ecdsa bech32

# Step 4: Transfer the script (choose one method)

# Method A — paste directly in Termux
nano ~/wif_forensic.py
# (paste the script content, then Ctrl+X → Y → Enter to save)

# Method B — from a PC via USB (requires adb)
adb push wif_forensic.py /sdcard/
cp /sdcard/wif_forensic.py ~/

# Method C — from a local-network PC (no internet needed)
# On PC: python -m http.server 8080 (in the directory containing the script)
# In Termux: curl http://192.168.x.x:8080/wif_forensic.py -o ~/wif_forensic.py

# Step 5: Make executable and run
chmod +x ~/wif_forensic.py
python ~/wif_forensic.py
```

> **⚠️ Before running:** Turn off Wi-Fi and mobile data. Go to Settings → Wi-Fi → Disconnect. Go to Settings → Mobile Network → Disable.

---

### On Desktop Linux / macOS — Secondary Target

```bash
# Requires Python 3.7+
python3 --version

# Install dependencies
pip3 install ecdsa bech32

# Run
python3 wif_forensic.py
```

---

### On Windows

```powershell
# Requires Python 3.7+ from python.org
python --version

# Install dependencies
pip install ecdsa bech32

# Run
python wif_forensic.py
```

> **Note on Windows:** The `"fork"` multiprocessing method is unavailable on Windows. The script automatically falls back to `"spawn"`, which works correctly but has slightly higher startup overhead per worker process. Results remain fully deterministic.

---

### Dependencies

| Library | Purpose | Stdlib? |
|---|---|---|
| `ecdsa` | secp256k1 scalar multiplication for public key derivation | No — `pip install ecdsa` |
| `bech32` | Bech32 encoding for native SegWit (`bc1q`) addresses | No — `pip install bech32` |
| `hashlib` | SHA-256 and RIPEMD-160 hashing | Yes (Python stdlib) |
| `multiprocessing` | Parallel brute-force across CPU cores | Yes (Python stdlib) |
| `itertools` | Cartesian product generation for candidate space | Yes (Python stdlib) |

---

## 🚀 Usage & Examples

```
python wif_forensic.py
```

The tool prompts for a single WIF string. Use `?` as a placeholder for any unknown character.

---

### Example 1 — Validating a Complete WIF

```
Enter WIF (or WIF with '?' placeholders): KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
```

**When to use:** You have a complete WIF from a backup and want to verify it is uncorrupted before importing it into a wallet.

---

### Example 2 — One Unknown Character

```
Enter WIF (or WIF with '?' placeholders): KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP9861?
```

**When to use:** You have a WIF written on paper and the last character is illegible. The tool tries all 58 possible Base58 characters for that position and returns only the one(s) that produce a valid checksum.

---

### Example 3 — Two Unknown Characters (parallel brute-force)

```
Enter WIF (or WIF with '?' placeholders): KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP986??
```

**When to use:** Two characters are smudged, scratched, or missing. 3,364 candidates are checked across all available CPU cores. Completes in under 1 second on a modern device.

---

### Example 4 — Three Unknown Characters (full parallel recovery)

```
Enter WIF (or WIF with '?' placeholders): KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98???
```

**When to use:** Three characters are corrupted. 195,112 candidates across all CPU cores. Completes in 4–10 seconds depending on device.

---

### Example 5 — Diagnosing a Corrupted Key

```
Enter WIF (or WIF with '?' placeholders): KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP980000
```

**When to use:** You have a WIF that your wallet software rejects and you want to know exactly why — length mismatch, invalid characters, or checksum failure.

---

## 📋 Reading the Output

### Validation Mode Output

```
══════════════════════════════════════════════════════════════════════
  Input Summary
══════════════════════════════════════════════════════════════════════
  Input:                       KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
  Length:                      52 characters
  Placeholders (?):            0
  Invalid chars:               None ✓

▸ Analysis Result
──────────────────────────────────────────────────────────────────────
  WIF:                         KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
  Status:                      ✓ VALID (checksum passed)
  Embedded checksum:           a62019d2
  Computed checksum:           ✓ a62019d2

  Key Details:
  Network:                     Mainnet (version byte 0x80)
  Private key (hex):           0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
  Compression flag:            Compressed

  Public key (compressed):     02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c

  Derived Addresses:
    P2PKH (Legacy):              1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK
    P2SH-P2WPKH (SegWit wrapped): 3D9iyFHi1Zs9KoyynUfrL82rGhJfYTfSG4
    P2WPKH (Native SegWit):      bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd
```

**Field explanations:**

| Field | What it means |
|---|---|
| `Status: ✓ VALID` | The embedded checksum exactly matches the recomputed checksum — the key is intact |
| `Status: ✗ INVALID` | Checksum mismatch, wrong length, or illegal characters |
| `Embedded checksum` | The 4 bytes baked into the WIF string itself by whoever originally encoded it |
| `Computed checksum` | What the checksum *should* be for this payload, calculated fresh by the tool |
| `Network` | Mainnet (real Bitcoin) or Testnet (practice network), decoded from the version byte |
| `Private key (hex)` | The raw 32-byte private key as a 64-character hex string |
| `Compression flag` | Whether this WIF encodes a preference for the compressed or uncompressed public key |
| `Public key (compressed)` | The 33-byte compressed public key derived via secp256k1 |
| `P2PKH (Legacy)` | The `1...` address — oldest format, widest compatibility |
| `P2SH-P2WPKH` | The `3...` address — SegWit wrapped in P2SH for backward compatibility |
| `P2WPKH (Native SegWit)` | The `bc1q...` address — lowest fees, newest wallets |

---

### Recovery Mode Output

```
══════════════════════════════════════════════════════════════════════
  Recovery Mode
══════════════════════════════════════════════════════════════════════
  CPU cores available:         8
  Worker processes:            8
  Max unknowns allowed:        3

[*] Brute-forcing 2 unknown(s) at position(s) [50, 51]
    3,364 candidates  ·  8 worker process(es)
  Worker chunk 1/8 done  (421/3,364 · 13%)
  Worker chunk 2/8 done  (841/3,364 · 25%)
  ...
  Worker chunk 8/8 done  (3,364/3,364 · 100%)

  Checked 3,364 candidates in 0.18s (18,689/s)

[✓] Found 1 valid candidate(s):

▸ Candidate 1/1
──────────────────────────────────────────────────────────────────────
  WIF:                         KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
  Status:                      ✓ VALID (checksum passed)
  ...
```

**What each line means:**

| Field | What it means |
|---|---|
| `CPU cores available` | How many logical CPU cores the OS reports for this device |
| `Worker processes` | How many parallel processes were actually spawned (capped at 8) |
| `position(s) [50, 51]` | The zero-indexed character positions in your input string that were `?` |
| `3,364 candidates` | Total combinations checked: `58^2 = 3,364` for 2 unknowns |
| `Worker chunk N/M done` | Progress reporting — each chunk completes when its worker process finishes |
| `18,689/s` | Throughput: candidates validated per second across all workers |
| `Found 1 valid candidate` | Exactly one string passed Base58Check — almost certainly your original key |
| `Found 0 valid candidates` | No string in the search space passes — more characters are corrupted than you marked |
| `Found N > 1 candidates` | Rare but possible — multiple strings pass the checksum. Verify against a known address |

---

### Failure Diagnostic Output

When a WIF fails, the tool tells you exactly why:

```
▸ Pre-Validation Failures
──────────────────────────────────────────────────────────────────────
  • Length: 54 characters (expected 51 or 52)
  • Invalid characters: ['0', 'O']
    Base58 excludes: 0 (zero), O (capital-o), I (capital-i), l (lowercase-L)
```

| Failure type | Likely cause |
|---|---|
| Wrong length | Extra characters copied in, or truncation during transcription |
| Invalid characters | Confused `0` with `o`, `I` with `l`, or copied from a non-Base58 source |
| Checksum mismatch | One or more characters are wrong, but the format is otherwise correct — use recovery mode |

---

## 🔄 Recovery Mode & Brute-Force Explained

### Why the Search Space Is Exponential

The Base58 alphabet has **58 characters**. For each unknown position, there are 58 possible values. Two unknowns means `58 × 58 = 3,364` combinations. Three means `58 × 58 × 58 = 195,112`. Four would be `~11.3 million`. The growth is exponential — each additional unknown multiplies the work by 58.

| Unknowns | Candidates | Time (8 cores) | Permitted? |
|---|---|---|---|
| 1 | 58 | < 0.1s | ✅ Yes |
| 2 | 3,364 | < 0.5s | ✅ Yes |
| 3 | 195,112 | 2–10s | ✅ Yes |
| 4 | 11,316,496 | ~10 min | ❌ No |

The hard cap at 3 unknowns is a deliberate safety and performance constraint. If 4 or more of your characters are corrupted, this tool cannot help — and it says so clearly rather than running for hours.

### Why Checksum Acts as a Perfect Filter

The 4-byte checksum has `2^32 ≈ 4.3 billion` possible values. The probability that a randomly modified WIF accidentally passes the checksum is about `1 in 4.3 billion`. In practice, for a 2-unknown search of 3,364 candidates, you would expect to find exactly **1 valid match** — your original key. Finding 0 means more characters are wrong than you marked. Finding more than 1 is statistically extraordinary (probability ≈ `3,364 / 4,294,967,296 ≈ 0.000078%`) but worth investigating if it occurs.

---

## ⚙️ Multiprocessing Design

The parallel brute-force is engineered for **deterministic output** — the results are always in the same order regardless of which CPU core finishes first.

### How Determinism Is Preserved

1. The full Cartesian product (`itertools.product(BASE58, repeat=N)`) is pre-generated as a list **before** any worker process is spawned. This fixes the order.
2. The list is split into `N_workers` contiguous, non-overlapping slices (chunks). Chunk boundaries are identical on every run.
3. `Pool.map()` dispatches one chunk per worker and **returns results in submission order** — not completion order. A fast worker finishing chunk 4 before chunk 2 does not change the output order.
4. The parent process flattens the per-chunk result lists in submission order to produce the final candidate list.

This means: if you run the tool three times with the same input, you always get the same candidates in the same order.

### Process Architecture

```
Main process
├── Pre-generates all combo chunks (deterministic)
├── Spawns Pool of N worker processes
│   ├── Worker 1 ← chunk 1 (combos 0 to K)
│   ├── Worker 2 ← chunk 2 (combos K+1 to 2K)
│   ├── ...
│   └── Worker N ← chunk N (combos (N-1)K+1 to end)
├── Pool.map() blocks until ALL workers complete
├── Results collected IN SUBMISSION ORDER
└── Flattened → final candidate list (deterministic)
```

### Platform Notes

| Platform | Start method | Notes |
|---|---|---|
| Linux / Android (Termux) | `fork` | Fast — workers inherit parent memory; no re-import of libraries |
| macOS (Python 3.8+) | `spawn` | Default changed in 3.8; slightly slower startup per worker |
| Windows | `spawn` | Only option; requires `if __name__ == "__main__":` guard (present) |

---

## 🛡️ Security Constraints & What This Tool Won't Do

These are not limitations — they are intentional design decisions.

| Constraint | Reason |
|---|---|
| **No network calls** | A tool that handles private keys must never touch the network. Verified by reading the imports: `socket`, `urllib`, `requests`, `httpx` are absent. |
| **No file output** | The tool writes nothing to disk by default. Avoiding persistent key storage prevents accidental exposure. |
| **Hard cap of 3 unknowns** | Prevents misuse as a general brute-force tool. 4+ unknowns require specialised hardware and are outside the scope of forensic key repair. |
| **No BIP-38 support** | Password-encrypted keys (BIP-38) require knowing the passphrase. This tool does not attempt passphrase brute-force. |
| **No transaction signing** | Out of scope. Signing requires interaction with the Bitcoin network and is not a forensic function. |
| **No address-to-key reversal** | This is mathematically impossible. HASH160 is a one-way function. |
| **No clipboard access** | The tool reads only from `stdin`. It does not access your clipboard. |

---

## 📐 Function Reference

| Function | Inputs | Returns | Purpose |
|---|---|---|---|
| `sha256(data)` | `bytes` | `bytes` (32) | Single SHA-256 hash |
| `double_sha256(data)` | `bytes` | `bytes` (32) | SHA256(SHA256(data)) — Bitcoin's standard |
| `hash160(data)` | `bytes` | `bytes` (20) | RIPEMD160(SHA256(data)) — address hash |
| `base58_encode(data)` | `bytes` | `str` | Raw bytes → Base58 string |
| `base58_decode(s)` | `str` | `bytes` or `None` | Base58 string → raw bytes; None on bad chars |
| `base58check_encode(payload)` | `bytes` | `str` | Payload → Base58Check string (adds checksum) |
| `base58check_decode(s)` | `str` | `(payload, checksum, valid, error)` | Full decode with checksum verification |
| `validate_wif_string(wif)` | `str` | `(bool, str)` | Pre-flight format check before decode |
| `extract_key_info(payload)` | `bytes` | `dict` or `None` | Parse version byte, raw key, compression flag |
| `derive_public_key(raw_key, compressed)` | `bytes, bool` | `bytes` or `None` | secp256k1 scalar multiplication |
| `p2pkh_address(pubkey)` | `bytes` | `str` | Derive Legacy `1...` address |
| `p2sh_p2wpkh_address(pubkey)` | `bytes` | `str` | Derive SegWit-wrapped `3...` address |
| `p2wpkh_address(pubkey)` | `bytes` | `str` | Derive Native SegWit `bc1q...` address |
| `analyze_wif(wif)` | `str` | `dict` | Full pipeline: decode → validate → derive |
| `_partition_combos(n, workers)` | `int, int` | `list[list[tuple]]` | Split product space into deterministic chunks |
| `_worker_validate_chunk(args)` | `tuple` | `list[dict]` | Worker entry point — validates one chunk |
| `recover_candidates(template)` | `str` | `list[dict]` | Parallel brute-force coordinator |

---

## 🔧 Troubleshooting

### `ModuleNotFoundError: No module named 'ecdsa'`
```bash
pip install ecdsa
# or on some systems:
pip3 install ecdsa
```

### `ModuleNotFoundError: No module named 'bech32'`
```bash
pip install bech32
```

### `ValueError: unsupported hash type ripemd160`
RIPEMD-160 is not compiled into some Android Python builds. Fix:
```bash
pkg install openssl
```
Then re-run the script.

### `OSError: [Errno 12] Cannot allocate memory`
Termux ran out of RAM while spawning worker processes. Close other apps and retry. The script always runs correctly with 1 worker even if spawning additional workers fails.

### Progress bar shows `0%` for a long time
Normal for 3-unknown searches — the entire product space is generated before workers start. The generation step takes ~0.5s and produces ~11 MB of data in memory before dispatch begins.

### Colors don't display (shows `\033[92m` literally)
Your terminal doesn't support ANSI escape codes. You can strip them:
```bash
python wif_forensic.py | sed 's/\x1b\[[0-9;]*m//g'
```

### `RuntimeError: An attempt has been made to start a new process before the current process has finished its bootstrapping phase`
You ran the script on Windows without the `if __name__ == "__main__":` guard. This guard is already present in the script. Make sure you are running `python wif_forensic.py` directly, not importing it from another script that lacks the guard.

### The tool finds 0 candidates but I'm sure the key is correct
More than 3 characters may be corrupted. Or the characters you're certain about may actually contain errors too. Try:
1. Moving the `?` to different positions — maybe the error is not where you think it is
2. Double-checking known characters — especially `0/O`, `I/l/1`, `5/S`, `8/B`
3. Checking that the total WIF length (with `?` counted as 1 char each) is 51 or 52

---

## 📁 Repository Structure

```
wif-forensic/
├── README.md              ← This file
├── wif_forensic.py        ← Main script (single-file, no package structure needed)
├── CHANGELOG.md           ← Version history and release notes
├── SECURITY.md            ← Extended private key security guidance
└── docs/
    ├── QUICKSTART.md      ← Get running in 2 minutes (fast-track guide)
    ├── INDEX.md           ← Complete package index and navigation
    ├── HOW_IT_WORKS.md    ← Deep technical walkthrough of the algorithms
    └── GLOSSARY.md        ← Standalone blockchain glossary for reference
```

---

## ⚖️ License & Disclaimer

This software is released for **educational and personal wallet recovery purposes only**.

The authors accept no responsibility for:
- Funds lost due to incorrect use of this tool
- Private key exposure resulting from running this tool on a connected device
- Any use of this tool for purposes other than recovery of keys you own

**You are solely responsible for the security of your private keys.**

> This tool is open-source so you can verify it does exactly what it claims and nothing else. Read the source. Trust the math, not the author.
