# HOW IT WORKS — Technical Deep Dive

> This document explains the algorithms inside WIF Forensic in step-by-step detail. It is written for developers, QA engineers, and anyone who wants to understand **why** each operation is performed, not just **what** it does.

---

## Overview of the Pipeline

WIF Forensic implements two modes that share the same core decoding pipeline:

```
Input WIF string
     │
     ├─── [Validation Mode]  ─── One string → analyze → display
     │
     └─── [Recovery Mode]    ─── N×58 candidates → filter by checksum → analyze valid ones → display
```

The core pipeline — `base58_decode → checksum_verify → key_extract → pubkey_derive → address_generate` — is identical in both modes. Recovery mode just calls it many times and discards failures.

---

## Stage 1 — Pre-Validation

**Function:** `validate_wif_string(wif)`

Before attempting any cryptographic operation, the tool makes two cheap checks:

### 1a. Length Check

```python
WIF_LENGTHS = {51, 52}
if len(wif) not in WIF_LENGTHS:
    return False, "..."
```

A WIF string is always exactly one of two lengths:
- **52 characters** — mainnet compressed (version `0x80` + 32-byte key + `0x01` flag = 34-byte payload + 4-byte checksum = 38 bytes → encodes to ~52 Base58 chars)
- **51 characters** — mainnet uncompressed (version `0x80` + 32-byte key = 33-byte payload + 4-byte checksum = 37 bytes → ~51 Base58 chars)

If the length is wrong, the tool immediately explains the discrepancy — no decoding attempted.

### 1b. Character Set Check

```python
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
invalid_chars = [ch for ch in wif if ch not in BASE58_SET]
```

Any character outside the 58-character Bitcoin alphabet is flagged. The excluded characters (`0`, `O`, `I`, `l`) are specifically named in the error message because they are the most common transcription errors.

---

## Stage 2 — Base58 Decoding

**Function:** `base58_decode(s)`

Base58 decoding is the inverse of Base58 encoding. The tool implements this from scratch — no external library is used for this operation.

### Step-by-Step

**1. Count leading `'1'` characters → they represent leading zero bytes**

```python
leading_ones = 0
for ch in s:
    if ch == "1":
        leading_ones += 1
    else:
        break
```

In Base58, a leading `1` encodes a leading zero byte in the raw data. This is a special case needed because a pure integer representation would lose leading zeros (the integer `0x0000...00FF` and `0xFF` would encode identically without this convention).

**2. Convert the Base58 string to a large integer**

```python
num = 0
for ch in s:
    num = num * 58 + BASE58_ALPHABET.index(ch)
```

This is positional numeral conversion, identical to how you would convert a decimal string to an integer — except the base is 58 instead of 10. Each character is a "digit" in base 58.

**3. Convert the integer to bytes**

```python
byte_length = (num.bit_length() + 7) // 8
decoded = num.to_bytes(byte_length, "big")
```

`bit_length()` gives the number of bits needed to represent the integer. `(n + 7) // 8` is ceiling division by 8 — the minimum number of bytes needed.

**4. Prepend the leading zero bytes**

```python
return (b"\x00" * leading_ones) + decoded
```

The leading `1` characters from step 1 become leading `\x00` bytes.

**Full example:** Decoding `KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617`

The result is 38 bytes of raw binary data containing:
- 1 byte: version (`0x80`)
- 32 bytes: raw private key
- 1 byte: compression flag (`0x01`)
- 4 bytes: checksum

---

## Stage 3 — Base58Check Verification

**Function:** `base58check_decode(s)`

```python
raw    = base58_decode(s)          # 38 bytes
payload   = raw[:-4]               # first 34 bytes
embedded  = raw[-4:]               # last 4 bytes (the checksum baked in)
computed  = double_sha256(payload)[:4]   # what it should be
```

### Why Double SHA-256?

Bitcoin uses `SHA256(SHA256(data))` (called SHA256d or double-SHA256) for checksums throughout the protocol. The original rationale was protection against length-extension attacks, which affect single SHA-256 but not double-SHA-256. For a 4-byte checksum used only for error detection (not authentication), the security difference is theoretical — but the convention is established and consistent.

### The Checksum Comparison

```python
if embedded == computed:
    return payload, embedded, True, ""
else:
    return payload, embedded, False, f"Checksum mismatch — embedded: {embedded.hex()}, computed: {computed.hex()}"
```

Both the embedded and computed checksums are shown in hex so you can see exactly how they differ. Even a single wrong character in the WIF string will produce a completely different computed checksum (this is the avalanche effect of SHA-256).

**Example of a checksum mismatch:**
- Embedded (from the corrupted WIF): `a62019d2`
- Computed (from the actual payload):  `fb3a8c11`

These being different proves the payload was corrupted during transcription.

---

## Stage 4 — Key Extraction

**Function:** `extract_key_info(payload)`

The `payload` (after checksum is stripped) is either 33 or 34 bytes:

```
Byte 0:     Version byte
Bytes 1-32: Raw 256-bit private key (32 bytes)
Byte 33:    (Optional) 0x01 = compressed key preference
```

```python
version_byte = payload[0]
raw_key      = payload[1:33]        # always exactly 32 bytes
compressed   = (len(payload) == 34 and payload[33] == 0x01)
```

### Version Byte Decoding

| Byte value | Network | WIF starts with |
|---|---|---|
| `0x80` (128) | Mainnet | `5` (uncompressed) or `K`/`L` (compressed) |
| `0xEF` (239) | Testnet | `9` (uncompressed) or `c` (compressed) |

The version byte is how you know whether a key is for real Bitcoin or the test network without needing any additional information.

---

## Stage 5 — Public Key Derivation

**Function:** `derive_public_key(raw_key, compressed=True)`

This is the cryptographic core of the tool.

### Elliptic Curve Scalar Multiplication

```python
signing_key   = ecdsa.SigningKey.from_string(raw_key, curve=SECP256K1)
verifying_key = signing_key.get_verifying_key()
```

Internally, the `ecdsa` library performs:

```
PublicKey_point = PrivateKey_scalar × G
```

Where:
- `PrivateKey_scalar` is the 256-bit integer from the raw key bytes
- `G` is the secp256k1 generator point (a fixed curve point defined in the secp256k1 specification)
- `×` is elliptic curve point multiplication (repeated point addition)
- `PublicKey_point` is a point `(X, Y)` on the curve

This operation is a **one-way function**: given `PublicKey_point` and `G`, recovering `PrivateKey_scalar` is the Elliptic Curve Discrete Logarithm Problem (ECDLP), which is computationally infeasible for 256-bit curves.

### Compressed Public Key Encoding

```python
x = verifying_key.pubkey.point.x()
y = verifying_key.pubkey.point.y()
prefix = b"\x02" if y % 2 == 0 else b"\x03"
return prefix + x.to_bytes(32, "big")
```

On the secp256k1 curve, for any X coordinate there are at most 2 valid Y values — one even, one odd. Instead of storing both (65 bytes), we store only X (32 bytes) plus a 1-byte prefix that encodes whether Y is even (`0x02`) or odd (`0x03`). The receiver can reconstruct the full point by solving the curve equation. This is the **compressed public key** format, now used by all modern Bitcoin wallets.

---

## Stage 6 — Address Generation

Three address formats are generated from the same compressed public key.

### 6a. P2PKH — Legacy Address (`1...`)

**Function:** `p2pkh_address(pubkey)`

```python
h160    = hash160(pubkey)            # RIPEMD160(SHA256(pubkey)) → 20 bytes
payload = b"\x00" + h160            # 0x00 = mainnet P2PKH version byte
return base58check_encode(payload)  # Base58Check encode with checksum
```

`HASH160` is the composition of SHA-256 and RIPEMD-160:
- SHA-256 produces 32 bytes
- RIPEMD-160 hashes that to 20 bytes

The dual hash serves belt-and-suspenders security: if SHA-256 is compromised, RIPEMD-160 still provides protection, and vice versa.

**Why `0x00` prefix?** The version byte `0x00` tells Base58Check that this is a mainnet P2PKH address. When encoded, `0x00 + 20 bytes + 4-byte checksum` = 25 bytes, which encodes to approximately 34 Base58 characters starting with `1`.

---

### 6b. P2SH-P2WPKH — SegWit Wrapped Address (`3...`)

**Function:** `p2sh_p2wpkh_address(pubkey)`

```python
h160          = hash160(pubkey)
redeem_script = b"\x00\x14" + h160     # OP_0 PUSH20 <hash>
script_hash   = hash160(redeem_script)
payload       = b"\x05" + script_hash  # 0x05 = mainnet P2SH version byte
return base58check_encode(payload)
```

This is the "compatibility SegWit" format — it wraps a SegWit witness program inside a P2SH (Pay to Script Hash) envelope so that older wallets that don't understand native SegWit can still send to it.

**Breaking down the redeemScript:**
- `\x00` = `OP_0` (witness version 0)
- `\x14` = `PUSH 20 bytes` (0x14 = 20 decimal)
- `h160` = the 20-byte hash of the public key

This redeemScript is then itself hashed with HASH160 and wrapped in a P2SH envelope (version byte `0x05`). The spending transaction reveals the redeemScript, which the network interprets as a SegWit witness program.

---

### 6c. P2WPKH — Native SegWit Address (`bc1q...`)

**Function:** `p2wpkh_address(pubkey)`

```python
h160      = hash160(pubkey)
converted = bech32.convertbits(h160, 8, 5, True)    # 8-bit groups → 5-bit groups
return bech32.bech32_encode("bc", [0x00] + converted)  # witness version 0
```

**Why convert 8-bit to 5-bit groups?** Bech32 uses a 32-character alphabet (each character encodes 5 bits). The 20-byte (160-bit) hash needs to be repackaged from 8-bit bytes into 5-bit "characters" for Bech32 encoding. `convertbits(data, 8, 5, True)` handles this bit-packing with padding.

**The witness version byte:** `[0x00]` prepended to the converted data is the SegWit version 0 indicator. Future script types (Taproot, etc.) use higher witness version numbers.

**Bech32 advantages over Base58Check:**
- Case-insensitive (avoids uppercase/lowercase confusion)
- Better error detection — can detect and locate up to 4 errors
- No ambiguous characters (the 32-char alphabet is specifically chosen)
- Validates more errors than Base58Check for the same checksum size

---

## Stage 7 — Recovery Mode: Parallel Brute-Force

### Partitioning the Search Space

**Function:** `_partition_combos(n_unknown, n_workers)`

```python
all_combos = list(itertools.product(BASE58_ALPHABET, repeat=n_unknown))
chunk_size = (len(all_combos) + n_workers - 1) // n_workers  # ceiling division
return [all_combos[i:i+chunk_size] for i in range(0, len(all_combos), chunk_size)]
```

`itertools.product("ABC...xyz", repeat=2)` generates:
```
('1','1'), ('1','2'), ('1','3'), ..., ('1','z'),
('2','1'), ('2','2'), ..., ('z','z')
```
— all 3,364 pairs for 2 unknowns, in lexicographic order.

Converting this to a `list` before chunking is the key to **determinism**: the order is fixed, chunk boundaries are fixed, and therefore which worker gets which chunk is fixed on every run.

### Why Pool.map() Preserves Order

Python's `multiprocessing.Pool.map(func, iterable)` is defined to return results **in the same order as the input iterable**, regardless of the order in which worker processes complete. Internally it uses a result queue keyed by task index, reordering the results before returning.

```
Submission order:  [chunk_0, chunk_1, chunk_2, chunk_3]
                        ↓        ↓        ↓        ↓
Workers complete:  chunk_2, chunk_0, chunk_3, chunk_1   (any order)
                                                         ↓
Return value:      [result_0, result_1, result_2, result_3]  (restored order)
```

This means the final candidate list is always in the same alphabetical order as a single-threaded scan would produce, regardless of OS scheduling or which core finishes first.

### The Worker Function

**Function:** `_worker_validate_chunk(args)`

```python
def _worker_validate_chunk(args):
    wif_template, positions, combo_chunk = args
    valid_hits = []
    template_list = list(wif_template)
    for combo in combo_chunk:
        candidate = template_list[:]          # fresh copy per combo
        for pos, ch in zip(positions, combo):
            candidate[pos] = ch
        candidate_str = "".join(candidate)
        if len(candidate_str) not in WIF_LENGTHS:
            continue
        result = analyze_wif(candidate_str)
        if result and result["valid"]:
            valid_hits.append(result)
    return valid_hits
```

**Why a top-level function?** Python's multiprocessing uses `pickle` to serialize the function and its arguments when sending them to worker processes. Lambdas, closures, and nested functions cannot be pickled — only top-level module-level functions can. `_worker_validate_chunk` is therefore defined at module scope.

**Why a single tuple argument?** `Pool.map(func, iterable)` calls `func(item)` for each item. To pass multiple arguments per call, they must be packaged as a single item — a tuple. The worker immediately unpacks it.

**Why `template_list[:]` inside the loop?** `list[:]` is a shallow copy. Without it, every iteration of the inner loop would modify the same list object, corrupting subsequent iterations. The copy is cheap (52 elements) and correct.

### The `fork` vs `spawn` Context

```python
def _get_mp_context():
    try:
        return multiprocessing.get_context("fork")
    except (ValueError, AttributeError):
        return multiprocessing.get_context("spawn")
```

**`fork`** (Linux/Android): The worker process is created by cloning the parent process's entire memory space. This means `ecdsa`, `bech32`, and all constants are already loaded in the worker — no re-import cost. Very fast process startup.

**`spawn`** (Windows, some macOS): The worker starts as a fresh Python interpreter, re-imports the script, and then receives its function and arguments via pickle. Slower startup but required on platforms where `fork` is unavailable or unsafe (e.g., macOS with certain GUI frameworks).

### Single-Worker Fast Path

```python
if total <= 256:
    n_workers = 1
```

For 1 unknown (58 candidates), the overhead of spawning a process pool — creating processes, pickling data, inter-process communication — exceeds the work itself. The single-worker path calls `_worker_validate_chunk` directly in the main process, skipping all IPC overhead entirely.

---

## Why the 3-Unknown Cap Is a Design Choice, Not a Bug

The cap is not about computational impossibility — a modern CPU can check ~50,000 candidates per second. At that rate:
- 3 unknowns (195K candidates): ~4 seconds
- 4 unknowns (11.3M candidates): ~226 seconds (~4 minutes)
- 5 unknowns (656M candidates): ~13,120 seconds (~3.6 hours)

The cap is set at 3 because:

1. **Tool purpose** — WIF Forensic is a *forensic* tool for recovering known-mostly-correct keys with a small number of transcription errors. If more than 3 characters are wrong, the key needs a fundamentally different recovery approach.

2. **Safety** — allowing 5+ unknowns would turn this into a general-purpose brute-force tool, which is not its purpose and would be irresponsible.

3. **User experience** — a 4-minute wait for a result on a phone is a poor experience and likely to be interrupted before completing.

4. **Checksum as signal** — if you have more than 3 unknowns, the probability of the checksum being useful as a filter drops, and you may need to question whether your known characters are actually correct.

---

## The Full Call Graph

```
main()
├── validate_wif_string()          [format check]
├── analyze_wif()                  [validation mode]
│   ├── base58check_decode()
│   │   ├── base58_decode()
│   │   └── double_sha256()
│   ├── extract_key_info()
│   ├── derive_public_key()        [secp256k1 via ecdsa library]
│   ├── p2pkh_address()
│   │   ├── hash160()
│   │   └── base58check_encode()
│   │       ├── double_sha256()
│   │       └── base58_encode()
│   ├── p2sh_p2wpkh_address()
│   │   ├── hash160()  (×2)
│   │   └── base58check_encode()
│   └── p2wpkh_address()
│       ├── hash160()
│       └── bech32.bech32_encode()
│
└── recover_candidates()           [recovery mode]
    ├── _partition_combos()        [deterministic chunking]
    ├── Pool.map(
    │   _worker_validate_chunk,    [per-chunk worker]
    │   job_args                   [one arg-tuple per worker]
    │   )
    │   └── [each worker calls analyze_wif() on its chunk]
    └── flatten(chunk_results)     [in submission order]
```
