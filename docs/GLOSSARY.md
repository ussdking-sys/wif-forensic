# GLOSSARY.md — Blockchain & Bitcoin Technical Terms

> A comprehensive reference for technical terms encountered when working with Bitcoin private keys, addresses, and forensic key recovery. Each entry includes plain-language explanation, technical definition, and where/why it matters.

---

## A

### Address
**See:** Bitcoin Address, P2PKH, P2SH-P2WPKH, P2WPKH

### Address Generation
The cryptographic process of deriving a Bitcoin address from a public key.

**Plain English:** Converting your public key into a "deposit address" that you can share with others.

**Technical:** HASH160(pubkey) wrapped in a version byte and checksum, then encoded in Base58Check (legacy) or Bech32 (SegWit). Three formats exist; WIF Forensic derives all three from a single private key.

**Formula:**
```
Address = VersionByte || HASH160(PublicKey) → Base58Check or Bech32
```

---

## B

### Base58
A number system using 58 characters: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`

**Plain English:** A way of writing binary data as readable text, designed to avoid confusion between similar-looking characters.

**Technical:** Positional numeral system with base 58. Each character is a "digit." Conversion from bytes to Base58:
1. Treat the byte array as a big-endian integer
2. Repeatedly divide by 58, collect remainders as Base58 digits
3. Preserve leading zero bytes as leading '1' characters

**Why 58?** Excludes 0 (zero), O (capital O), I (capital I), l (lowercase L) — characters that look identical or nearly identical in most fonts. Prevents transcription errors.

**Example:** 38 raw bytes (a WIF) → ~52 Base58 characters

---

### Base58Check
Base58 encoding with a 4-byte checksum appended.

**Plain English:** Base58 with error detection built in.

**Technical:** 
1. Compute `SHA256(SHA256(payload))`, take first 4 bytes
2. Append checksum to payload
3. Base58-encode the combined data

On decode, recompute the checksum and compare. A single wrong character will almost certainly cause a checksum mismatch (probability of false match: ~1 in 4.3 billion).

**Used for:** WIF strings, Bitcoin addresses (P2PKH and P2SH-P2WPKH)

---

### Bech32
A newer encoding scheme for Bitcoin addresses, especially SegWit.

**Plain English:** An improved version of Base58Check with better error detection.

**Technical:**
- Uses 32-character alphabet: `qpzry9x8gf2tvdw0s3jn54khce6mua7l`
- Case-insensitive (avoids uppercase/lowercase confusion)
- BCH (Bose–Chaudhuri–Hocquenghem) checksum can detect up to 4 errors and locate their positions
- Format: HRP (human-readable part) + checksum + data
- Example: `bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd`

**Used for:** Native SegWit addresses (P2WPKH, P2WSH)

---

### Bitcoin Address
A string derived from your public key that you can share publicly. Anyone can send Bitcoin to this address, but only the holder of the corresponding private key can spend it.

**Three formats:**

| Format | Starts with | Encoding | Modern? |
|---|---|---|---|
| P2PKH (Legacy) | `1` | Base58Check | Oldest; widely supported |
| P2SH-P2WPKH | `3` | Base58Check | 2017; backward compatible SegWit |
| P2WPKH (Native SegWit) | `bc1q` | Bech32 | 2017+; lowest fees |

All three can be derived from the same private key. They produce different addresses but control the same funds.

---

### Bitcoin Mainnet
The real Bitcoin network where coins have market value and transactions are permanent.

**Technical:** Uses version bytes `0x80` (private key) and `0x00` (P2PKH address).

**Contrast:** Testnet (worthless coins for testing).

---

### Bitcoin Testnet
A separate Bitcoin network for development and testing, where coins are worthless.

**Technical:** Uses version bytes `0xEF` (private key) and `0x6F` (P2PKH address).

**Purpose:** Test wallet software, debug transactions, and experiment without financial risk.

---

## C

### Checksum
A short fingerprint derived from data that changes if the data is modified.

**Plain English:** A safety check that detects typos and corruption.

**Technical:** In Base58Check, the checksum is 4 bytes (32 bits) derived from `SHA256(SHA256(payload))`. The probability of a random string accidentally having the correct checksum is ~1 in 4.3 billion.

**Used in:** WIF encoding, Base58Check addresses

---

### Compressed Public Key
A 33-byte representation of a public key using a point's X coordinate plus a 1-byte parity indicator.

**Plain English:** A shorter way to write a public key, preserving the same information in less space.

**Technical:**
- On secp256k1, for every X coordinate there are 2 possible Y values (one even, one odd)
- Compressed format: `02` (even Y) or `03` (odd Y) + 32-byte X coordinate
- Receiver solves the curve equation to recover the full point
- Saves 32 bytes per key (~3% transaction size reduction, multiplied by millions of transactions)

**When WIF Forensic uses compressed keys:** Always, for address generation. Modern wallets prefer compressed keys.

---

### Compression Flag
A single byte (`0x01`) optionally appended to the WIF payload to indicate that the key should be used with a compressed public key.

**Technical:** WIF encoding:
```
Uncompressed: 0x80 || PrivKey || Checksum  (33 bytes + 4-byte checksum)
Compressed:   0x80 || PrivKey || 0x01 || Checksum  (34 bytes + 4-byte checksum)
```

Result: uncompressed WIFs are 51 characters, compressed are 52 characters.

**Why it matters:** The same private key produces different Bitcoin addresses when treated as compressed vs. uncompressed. WIF Forensic reports this flag and always derives addresses from the compressed form (modern standard).

---

## D

### Determinism
An algorithm that always produces the same output for the same input, regardless of execution environment or timing.

**Plain English:** If you run the tool three times with the same WIF template, you get identical results every time.

**Technical in WIF Forensic:** The candidate search space is pre-partitioned into chunks before workers are spawned. `Pool.map()` returns results in submission order (not completion order), ensuring the same alphabetical output regardless of CPU scheduling.

**Contrast:** Nondeterministic algorithms may produce different results on different runs.

---

### Double SHA-256 (SHA256d)
Applying SHA-256 twice: `SHA256(SHA256(data))`

**Plain English:** A "double hash" — like running data through a blender twice.

**Technical:** Used throughout Bitcoin for checksums and transaction hashing. The original rationale was protection against length-extension attacks (SHA-256 is vulnerable, but double-SHA-256 is not). For a 4-byte checksum, the difference is theoretical, but the convention is established.

**Formula:** `SHA256d(data) = SHA256(SHA256(data))`

---

## E

### ECDSA
Elliptic Curve Digital Signature Algorithm.

**Plain English:** The cryptographic system Bitcoin uses for signatures and key pairs.

**Technical:** A signature algorithm defined in FIPS 186-4. Bitcoin uses ECDSA on the secp256k1 curve. Produces a pair `(r, s)` that proves knowledge of the private key without revealing it.

**Key property:** Verification requires only the public key and message hash. The private key is never transmitted.

---

### Elliptic Curve
A mathematical curve of the form `y² = x³ + ax + b` over a finite field.

**Plain English:** A curve with special properties that make it useful for cryptography — specifically, for creating one-way functions.

**Why Bitcoin uses it:** Elliptic curve cryptography allows short keys (256 bits) with security equivalent to ~3072-bit RSA. Faster and more space-efficient than alternatives.

---

## F

### Fork (Multiprocessing)
A method of starting a new process by copying the parent process's entire memory space.

**Plain English:** The new worker process inherits everything the parent had — loaded libraries, variables, constants.

**Technical:** `os.fork()` on Unix-like systems (Linux, macOS, Android). The child process is a full clone, so no re-import or re-initialization is needed.

**Advantages:**
- Fast — no Python import overhead per worker
- Memory-efficient — copy-on-write for shared read-only data

**Available on:** Linux, Android (Termux), macOS (with some caveats)

**Not available on:** Windows

---

## G

### Generator Point (G)
A fixed point on the secp256k1 elliptic curve used as the base for all Bitcoin key pairs.

**Plain English:** A special number baked into Bitcoin that is used to convert private keys into public keys.

**Technical:** `G = (0x79BE667E..., 0x483ADA77...)` (coordinates in hex). Every public key is computed as `PublicKey = PrivateKey × G` (elliptic curve scalar multiplication). The fact that G is fixed means two different private keys will never produce the same public key.

---

## H

### Hash160
The combination of SHA-256 and RIPEMD-160.

**Plain English:** A two-step hashing process that compresses data down to 20 bytes.

**Technical:** 
```
HASH160(data) = RIPEMD160(SHA256(data))
```

SHA-256 produces 32 bytes, RIPEMD-160 hashes that to 20 bytes.

**Used for:** Deriving Bitcoin addresses from public keys

**Why two hashes?** Belt-and-suspenders: if one algorithm is ever broken, the other still provides security. Also, the 20-byte output is a practical size for addresses.

---

## I

### Invalid Character
Any character outside the Base58 alphabet or (in Bech32) outside the 32-character Bech32 alphabet.

**Common mistakes in WIF transcription:**
- `0` (zero) instead of `O` (capital O)
- `l` (lowercase L) instead of `I` (capital I) or `1` (one)
- `I` (capital I) instead of `l` (lowercase L)
- `S` instead of `5`
- `B` instead of `8`

WIF Forensic flags all invalid characters and names the excluded ones explicitly.

---

## J

### JSON
JavaScript Object Notation — a text format for structured data.

**Note:** WIF Forensic does not output JSON. It outputs colored terminal text for readability. The tool is designed for human interpretation, not machine parsing (though parsing the colored output is possible by stripping ANSI codes).

---

## K

### Key Derivation
The process of converting a private key into a public key.

**Plain English:** The mathematical operation that transforms your secret into your public identifier.

**Technical:** On secp256k1: `PublicKey = PrivateKey × G` (scalar multiplication on the elliptic curve).

**Property:** One-way — given the public key and G, recovering the private key requires solving ECDLP, which is computationally infeasible.

---

## L

### Legacy Address
A Bitcoin address in the P2PKH format, starting with `1`.

**Plain English:** The oldest kind of Bitcoin address. Still widely supported but no longer recommended for new transactions.

**Technical:** `Base58Check(0x00 || HASH160(PublicKey))`

**Size:** ~34 Base58 characters

**Transaction size:** Slightly larger than SegWit, leading to higher fees

---

## M

### Mainnet
See: Bitcoin Mainnet

### Multiprocessing
Dividing work across multiple CPU processes to run in parallel.

**Plain English:** Using all the cores in your CPU at the same time instead of just one.

**Technical in WIF Forensic:** The candidate search space is split into N chunks (N = number of CPU cores), each dispatched to a worker process via `multiprocessing.Pool`. Workers validate candidates in parallel; results are collected in submission order for deterministic output.

**Constraint:** Multiprocessing has overhead (IPC, pickling, context switching). For small search spaces (<256 candidates), single-process execution is faster.

---

## N

### Native SegWit
A Bitcoin address using the newer SegWit v0 script type, encoded in Bech32 and starting with `bc1q`.

**Plain English:** The modern standard for receiving Bitcoin.

**Technical:** `Bech32(0 || HASH160(PublicKey))` where `0` is the witness version

**Advantages:**
- Lowest transaction fees (smaller script)
- Better error detection (Bech32 checksum)
- Case-insensitive

**Disadvantage:** Not supported by older wallets (pre-2017)

---

### Network Version Byte
The first byte of a WIF or address payload that indicates whether it's for Mainnet or Testnet.

**For WIF:**
| Byte | Network | WIF starts with |
|---|---|---|
| `0x80` (128) | Mainnet | `5` or `K`/`L` |
| `0xEF` (239) | Testnet | `9` or `c` |

**For addresses:**
| Byte | Network | Address starts with |
|---|---|---|
| `0x00` | Mainnet P2PKH | `1` |
| `0x05` | Mainnet P2SH | `3` |
| `0x6F` | Testnet P2PKH | `m` or `n` |

---

## O

### One-Way Function
A function that is easy to compute in one direction but computationally infeasible to reverse.

**Examples in Bitcoin:**
- SHA-256: easy to compute, infeasible to reverse (find input given output)
- HASH160: easy to compute, infeasible to reverse
- ECDLP (elliptic curve discrete logarithm): easy to compute `PublicKey = PrivateKey × G`, infeasible to compute `PrivateKey = PublicKey / G`

**Why they matter:** Bitcoin's security relies on these one-way functions being genuinely infeasible to reverse with current and near-future technology.

---

## P

### P2PKH
Pay to Public Key Hash.

**Plain English:** Bitcoin's oldest address format.

**Technical:** 
```
Address = Base58Check(0x00 || HASH160(PublicKey))
```

- Version byte: `0x00` (mainnet)
- Payload: 20-byte HASH160
- Final: 25 bytes → ~34 Base58 characters
- Starts with: `1`

**How spending works:** The spender provides the public key and a signature. The network verifies that the signature is valid for that public key, and that HASH160(pubkey) matches the address.

---

### P2SH-P2WPKH
Pay to Script Hash — SegWit Wrapped.

**Plain English:** A newer address format that looks like a P2SH address but contains a SegWit witness script, providing backward compatibility.

**Technical:**
```
RedeemScript = OP_0 || PUSH20 || HASH160(PublicKey)
Address = Base58Check(0x05 || HASH160(RedeemScript))
```

- Version byte: `0x05` (mainnet P2SH)
- Payload: 20-byte HASH160 of the redeemScript
- Final: 25 bytes → ~34 Base58 characters
- Starts with: `3`

**Advantage:** Works with wallets that don't understand native SegWit (backwards compatible) but still provides SegWit fee benefits.

---

### P2WPKH
Pay to Witness Public Key Hash — Native SegWit.

**Plain English:** The modern, most efficient address format.

**Technical:**
```
Address = Bech32("bc" || HASH160(PublicKey))
```

- Encoding: Bech32
- HRP (human-readable part): `bc` (mainnet) or `tb` (testnet)
- Witness version: 0
- Payload: 20-byte HASH160
- Starts with: `bc1q` (mainnet) or `tb1q` (testnet)

**Advantages:**
- Smallest transaction size → lowest fees
- Best error detection (Bech32)
- Case-insensitive

---

### Payload
The data portion of a WIF or address, before the checksum is appended.

**For WIF:**
```
WIF (52 chars) ← Base58Check ← Payload (34 bytes) ← Version + Key + Flag
```

**For address:**
```
Address ← Base58Check or Bech32 ← Payload (20 bytes) ← Version + HASH160
```

---

### Pickle (Python)
Python's object serialization format.

**Plain English:** A way to convert Python objects into bytes so they can be sent between processes or stored to disk.

**Technical in WIF Forensic:** When `multiprocessing.Pool` sends a worker function and arguments to a child process, they are pickled (converted to bytes), sent via IPC, and unpickled in the worker. This is why the worker function must be a top-level, importable function (not a lambda or closure).

---

### Private Key
A 256-bit random number that controls a Bitcoin wallet.

**Plain English:** Your secret password. Anyone with this can steal all your funds.

**Technical:** An integer in the range `[1, n-1]` where `n` is the order of the secp256k1 curve. Typically written as 64 hexadecimal characters (32 bytes).

**Properties:**
- Unique — no two people should generate the same one
- Chosen at random — not derived from a password
- One-way — cannot be recovered from the public key or address

**SECURITY:** Never share, never paste into a connected device, never store unencrypted.

---

### Public Key
A value derived from the private key that proves you own the key without revealing it.

**Plain English:** Your public identifier.

**Technical:** A point on the secp256k1 elliptic curve, computed as `PublicKey = PrivateKey × G`. Can be compressed (33 bytes) or uncompressed (65 bytes).

**Property:** Can be shared freely; mathematically bound to the private key but infeasible to reverse.

---

## Q

### Qubits / Quantum
**Note:** Not relevant to this tool. Quantum computers do not threaten Bitcoin's security in practical timeframes (decades or more). If they do become powerful enough to threaten ECDLP, Bitcoin will migrate to quantum-resistant algorithms before such computers exist.

---

## R

### Raw Key
The pure 32-byte private key before any encoding.

**Plain English:** The naked secret, before it's wrapped in a WIF format.

**Technical:** A 256-bit integer represented as 32 bytes (big-endian).

**In WIF Forensic output:**
```
Private key (hex): 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
```

This is the raw key in hexadecimal (64 characters = 32 bytes × 2 hex digits per byte).

---

### Recovery Mode
The tool's brute-force mode, activated when the input contains `?` placeholders.

**Plain English:** Trying all possible characters for the unknown positions and returning which one(s) produce a valid checksum.

**Technical:** Pre-partitions the Cartesian product `BASE58_ALPHABET ^ N_unknowns` into chunks, dispatches to worker processes, filters results by checksum validation, and returns all valid candidates.

**Constraint:** Limited to 3 unknowns (195,112 candidates max) for safety and performance.

---

### RedeemScript
A script embedded inside a P2SH address that defines how the funds can be spent.

**In P2SH-P2WPKH:**
```
RedeemScript = OP_0 || PUSH20 || HASH160(PublicKey)
Address = Base58Check(0x05 || HASH160(RedeemScript))
```

When spending, the spender must provide the redeemScript in the transaction. The network hashes it and verifies it matches the address, then interprets it as a SegWit witness program.

---

### RIPEMD-160
A cryptographic hash function that produces a 160-bit (20-byte) output.

**Plain English:** A fingerprinting function — longer output than SHA-256, but still one-way.

**Technical:** Designed in 1996 by Hans Dobbertin, Antoon Bosselaert, and Bart Preneel. No known attacks. Bitcoin uses it in the `HASH160` combination for address generation.

**Size:** 160 bits = 20 bytes

**Used for:** Deriving Bitcoin addresses from public keys

---

## S

### Scalar Multiplication (Elliptic Curve)
The operation of multiplying a point on an elliptic curve by a scalar (regular integer).

**Plain English:** The mathematical process of converting a private key into a public key.

**Technical:** `PublicKey = PrivateKey × G` where `×` is repeated point addition on the secp256k1 curve. Not the same as integer multiplication — it's a specialized curve operation.

**Visualization:**
```
G = Generator point
PrivateKey = 123 (example)
PublicKey = G + G + G + ... + G (123 times)
```

(Implemented efficiently with double-and-add algorithm, not naive loops.)

---

### secp256k1
The elliptic curve used by Bitcoin.

**Plain English:** The specific mathematical curve that Bitcoin chose for its key pairs.

**Technical:** 
- Curve equation: `y² = x³ + 7` over the field `F_p` where `p = 2^256 - 2^32 - 977`
- Order of generator: `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
- Private key range: `[1, n-1]`

**Why "secp256k1"?** Standards for Efficient Cryptography (SEC), Proposed, Primary (1), Curve (p), 256-bit, K (Koblitz), 1 (first of this family).

**Security:** Provides ~128 bits of symmetric security (equivalent to AES-128 or SHA-256).

---

### SegWit (Segregated Witness)
A 2017 Bitcoin upgrade that separated signature data from transaction data.

**Plain English:** A change to how Bitcoin transactions are structured, resulting in lower fees and smaller block size.

**Technical:**
- Moves signature ("witness") data out of the base transaction
- Reduces transaction "weight" — fees are based on weight, not just byte size
- Enables new script types: P2WPKH, P2WSH
- Backward compatible (wrapped SegWit in P2SH)

**When:** Activated August 2017 (mainnet)

**Impact:** ~25% reduction in transaction size for SegWit transactions, ~33% for native SegWit vs. legacy P2PKH

---

### SHA-256
Secure Hash Algorithm 256-bit.

**Plain English:** A one-way fingerprinting function that takes any input and produces a fixed 32-byte output.

**Technical:** Cryptographic hash function from the SHA-2 family (FIPS 180-4). Change one bit of input and the output is completely different (avalanche effect). Infeasible to find two inputs with the same output (collision resistance).

**Used in Bitcoin for:**
- Transaction hashing
- Block hashing
- Checksum computation (double SHA-256)

**Output size:** 256 bits = 32 bytes = 64 hexadecimal characters

---

### Signature (ECDSA)
A pair `(r, s)` that proves knowledge of the private key without revealing it.

**Plain English:** A digital signature — proof that you authorized a transaction.

**Technical:** Generated by applying ECDSA to the transaction hash and the private key. Verified using only the public key, transaction hash, and signature — the private key is not needed.

**Size:** 64 bytes (32 bytes for r, 32 bytes for s), often encoded as DER format which is ~70 bytes.

---

### Spawn (Multiprocessing)
A method of starting a new process by creating a fresh Python interpreter and importing the script.

**Plain English:** The worker starts from scratch and reimports everything.

**Technical:** The parent serializes (pickles) the function and arguments, sends them to the child process, which deserializes them and calls the function.

**Advantages:**
- Works on Windows and platforms where `fork` is unavailable
- Isolated memory space

**Disadvantages:**
- Slower startup (requires re-import of libraries like `ecdsa`, `bech32`)
- More overhead per worker process

**Available on:** Windows, macOS (default in Python 3.8+), Linux (if explicitly requested)

---

## T

### Testnet
See: Bitcoin Testnet

### Transaction Hashing
The process of computing a transaction ID (txid) by double-SHA-256 hashing a transaction.

**Technical:** `txid = SHA256d(transaction_bytes)`

**Note:** WIF Forensic does not compute transaction hashes. It derives addresses from keys, not transactions.

---

## U

### Uncompressed Public Key
A 65-byte representation of a public key using both X and Y coordinates.

**Plain English:** The full form of a public key.

**Technical:**
- Format: `0x04 || 32-byte X || 32-byte Y`
- Size: 65 bytes
- Older wallets and protocols used this; modern wallets prefer compressed

**Relationship:** The compressed and uncompressed forms encode the same point; only the representation differs.

---

## V

### Version Byte
The first byte of a WIF or address that encodes:
1. Network (Mainnet or Testnet)
2. Address type (P2PKH, P2SH, etc.)

**See also:** Network Version Byte

---

## W

### WIF (Wallet Import Format)
A standardized format for encoding a Bitcoin private key as a string of Base58 characters.

**Plain English:** A way to write down a private key that is shorter and includes an error-check.

**Technical:**
```
WIF = Base58Check(VersionByte || PrivateKey || [CompressionFlag])
```

**Lengths:**
- Compressed: 52 characters (version + 32-byte key + 0x01 compression flag + 4-byte checksum = 38 bytes → ~52 Base58)
- Uncompressed: 51 characters (version + 32-byte key + 4-byte checksum = 37 bytes → ~51 Base58)

**Example:** `KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617`

**History:** Format standardized by various Bitcoin wallet implementations; now documented in various BIPs and Bitcoin Core source.

---

### Witness Version
The version number for a SegWit script type.

**Current:**
- `0` — Native SegWit (P2WPKH, P2WSH)

**Future:**
- `1` — Taproot (Schnorr signatures, script aggregation)
- `2+` — Reserved for future upgrades

**In P2WPKH:** `Bech32(0 || HASH160(pubkey))`

---

## X

### X Coordinate
The horizontal coordinate of a point on the elliptic curve.

**Plain English:** One half of the public key's position on the curve.

**Technical:** For the secp256k1 curve, there are two Y values for each X. The compressed public key stores only X plus a 1-byte indicator of which Y to use.

---

## Y

### Y Coordinate
The vertical coordinate of a point on the elliptic curve.

**Plain English:** The other half of the public key's position.

**Technical:** Solving `y² ≡ x³ + 7 (mod p)` recovers both possible Y values; the compression flag indicates which one to use.

---

## Z

### Zero Byte
A byte with value `0x00`.

**In Base58 encoding:** Leading zero bytes are encoded as leading `'1'` characters in Base58.

**Example:** A WIF string starting with `1111` (four ones) indicates the underlying data starts with four zero bytes.

---

## Symbols

### `||` (Concatenation)
In cryptographic notation, `||` means concatenation (joining of byte strings).

**Example:** `0x80 || key || 0x01` means: the byte 0x80, followed by the key bytes, followed by the byte 0x01.

---

### `×` (Elliptic Curve Multiplication)
In elliptic curve cryptography, `×` means scalar multiplication of a curve point.

**Example:** `PublicKey = PrivateKey × G` means: multiply the generator point G by the private key scalar (repeated point addition).

---

### `≡` (Congruence)
In modular arithmetic, `≡` means "is congruent to modulo."

**Example:** `y² ≡ x³ + 7 (mod p)` means: y squared is congruent to x cubed plus 7, modulo the prime p.

---

### `^` (Exponentiation or Bitwise XOR)
Context-dependent:
- In `58^N`: exponentiation (58 to the power N)
- In `a ^ b` (computers): bitwise XOR

**In WIF Forensic:** Always exponentiation when discussing candidate counts.

---

## Further Reading

- **Bitcoin Whitepaper:** https://bitcoin.org/bitcoin.pdf
- **FIPS 186-4 (ECDSA):** https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
- **BIP 173 (Bech32):** https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
- **BIP 141 (SegWit):** https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- **secp256k1 Specification:** https://en.wikipedia.org/wiki/Secp256k1
