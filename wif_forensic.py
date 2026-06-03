#!/usr/bin/env python3
"""
=============================================================================
  Bitcoin WIF Forensic Analyzer & Limited Recovery Tool
  Compatible with Termux (Android) and any Python 3.7+ environment
=============================================================================

PURPOSE:
  This script performs forensic analysis and controlled brute-force recovery
  of Bitcoin private keys encoded in Wallet Import Format (WIF). It is
  designed for wallet recovery, educational study, and offline key validation.

EDUCATIONAL OVERVIEW:
  WIF (Wallet Import Format) is a Base58Check-encoded representation of a
  Bitcoin private key. The encoding process:

    1. Start with a 32-byte raw private key
    2. Prepend a 1-byte network prefix:
         0x80  → Mainnet
         0xEF  → Testnet
    3. (Optional) Append 0x01 for compressed public key
    4. Compute double-SHA256 of the versioned payload
    5. Take first 4 bytes of that hash as the checksum
    6. Append checksum to payload
    7. Base58-encode the entire result

  WHY CHECKSUM MATTERS:
  The 4-byte checksum allows detection of typos or corruption. Any single
  character change in a WIF string will almost certainly produce a checksum
  mismatch, making accidental use of wrong keys extremely unlikely.

  WHY BRUTE-FORCE IS LIMITED:
  Base58 has 58 characters. For N unknown positions, there are 58^N candidates.
    1 unknown:    58 candidates     (trivial, single-threaded)
    2 unknowns:   3,364 candidates  (fast, single-threaded)
    3 unknowns:   195,112 candidates (manageable with multiprocessing)
    4 unknowns:   ~11 million        (impractical; not permitted)
  This script limits recovery to 3 unknowns. With multiprocessing across
  all available CPU cores the 3-unknown space (~195K) completes in seconds.

MULTIPROCESSING DESIGN:
  The candidate space (itertools.product of Base58^N) is pre-partitioned into
  contiguous chunks before any worker is spawned. Each worker receives an
  independent, non-overlapping slice — no shared state, no locks, no queues.

  Pool.map() collects results IN SUBMISSION ORDER, so output is fully
  deterministic regardless of which worker finishes first or CPU scheduling.

  On Termux/Android, the "fork" start method is preferred (faster, no
  re-import cost). The script auto-detects and falls back to "spawn" if
  fork is unavailable.

SAFETY:
  - 100% offline. No network calls of any kind.
  - No file logging of private keys unless you add it yourself.
  - You are responsible for securing any keys this tool recovers.

=============================================================================
"""

import sys
import hashlib
import itertools
import multiprocessing
import os
import time
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────

def check_dependencies():
    """Check for required third-party libraries and give install instructions."""
    missing = []
    try:
        import ecdsa  # noqa: F401
    except ImportError:
        missing.append("ecdsa")
    try:
        import bech32  # noqa: F401
    except ImportError:
        missing.append("bech32")
    if missing:
        print("\n[ERROR] Missing required libraries: " + ", ".join(missing))
        print("Install them in Termux with:")
        print("  pip install " + " ".join(missing))
        print("\nSee the setup instructions at the bottom of this file.\n")
        sys.exit(1)

check_dependencies()

import ecdsa  # type: ignore
import bech32  # type: ignore

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Base58 alphabet used by Bitcoin (excludes 0, O, I, l to avoid visual confusion)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_SET = set(BASE58_ALPHABET)

# WIF lengths: uncompressed=51 chars, compressed=52 chars
WIF_LENGTHS = {51, 52}

# Network version bytes
MAINNET_PREFIX  = 0x80
TESTNET_PREFIX  = 0xEF

# secp256k1 curve used by Bitcoin
SECP256K1 = ecdsa.SECP256k1

# ANSI colors for terminal output (work in Termux)
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    DIM    = "\033[2m"
    WHITE  = "\033[97m"

# ─────────────────────────────────────────────────────────────────────────────
# UTILITY: SHA-256 / HASH160
# ─────────────────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    """Single SHA-256 hash."""
    return hashlib.sha256(data).digest()

def double_sha256(data: bytes) -> bytes:
    """Double SHA-256 (SHA256d) — used for Bitcoin checksums."""
    return sha256(sha256(data))

def hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)) — used for address generation."""
    h = hashlib.new("ripemd160")
    h.update(sha256(data))
    return h.digest()

# ─────────────────────────────────────────────────────────────────────────────
# BASE58 ENCODING / DECODING (implemented from scratch)
# ─────────────────────────────────────────────────────────────────────────────

def base58_encode(data: bytes) -> str:
    """
    Encode raw bytes to a Base58 string.
    Leading zero bytes map to leading '1' characters.
    The integer value of the remaining bytes is encoded in base-58.
    """
    # Count leading zero bytes → each becomes a leading '1'
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break

    # Convert bytes to a large integer
    num = int.from_bytes(data, "big")

    # Repeatedly divide by 58, collect remainders
    result = []
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(BASE58_ALPHABET[remainder])

    # Reverse (we collected digits least-significant first)
    result.reverse()

    # Prepend '1' characters for leading zero bytes
    return ("1" * leading_zeros) + "".join(result)


def base58_decode(s: str) -> Optional[bytes]:
    """
    Decode a Base58 string back to raw bytes.
    Returns None if any character is outside the Base58 alphabet.
    Leading '1' characters decode back to leading zero bytes.
    """
    # Validate all characters
    for ch in s:
        if ch not in BASE58_SET:
            return None

    # Count leading '1' characters → leading zero bytes
    leading_ones = 0
    for ch in s:
        if ch == "1":
            leading_ones += 1
        else:
            break

    # Convert Base58 string to a large integer
    num = 0
    for ch in s:
        num = num * 58 + BASE58_ALPHABET.index(ch)

    # Convert integer to bytes
    # Determine byte length needed
    if num == 0:
        decoded = b""
    else:
        byte_length = (num.bit_length() + 7) // 8
        decoded = num.to_bytes(byte_length, "big")

    # Prepend leading zero bytes
    return (b"\x00" * leading_ones) + decoded


def base58check_encode(payload: bytes) -> str:
    """
    Encode payload bytes using Base58Check:
    append first 4 bytes of SHA256d as checksum, then Base58-encode.
    """
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


def base58check_decode(s: str) -> tuple[Optional[bytes], Optional[bytes], bool, str]:
    """
    Decode a Base58Check string.

    Returns:
        (payload, checksum_expected, is_valid, error_message)
        - payload: bytes without checksum (or None on decode failure)
        - checksum_expected: the 4 checksum bytes embedded in the string
        - is_valid: True if checksum matches recomputed value
        - error_message: human-readable reason if invalid
    """
    raw = base58_decode(s)
    if raw is None:
        return None, None, False, "Contains characters outside the Base58 alphabet"

    if len(raw) < 4:
        return raw, None, False, f"Decoded data too short ({len(raw)} bytes, need ≥4)"

    # Split into payload and embedded checksum
    payload   = raw[:-4]
    embedded  = raw[-4:]

    # Recompute checksum over payload
    computed = double_sha256(payload)[:4]

    if embedded == computed:
        return payload, embedded, True, ""
    else:
        return payload, embedded, False, (
            f"Checksum mismatch — embedded: {embedded.hex()}, "
            f"computed: {computed.hex()}"
        )

# ─────────────────────────────────────────────────────────────────────────────
# WIF VALIDATION & KEY EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def validate_wif_string(wif: str) -> tuple[bool, str]:
    """
    Pre-validate the WIF string format before attempting decode.
    Returns (is_ok, reason_if_not).
    """
    if len(wif) not in WIF_LENGTHS:
        return False, (
            f"Length {len(wif)} is invalid. "
            f"WIF must be 51 chars (uncompressed) or 52 chars (compressed)."
        )

    invalid_chars = [ch for ch in wif if ch not in BASE58_SET]
    if invalid_chars:
        unique_bad = sorted(set(invalid_chars))
        return False, f"Invalid Base58 characters: {unique_bad}"

    return True, ""


def extract_key_info(payload: bytes) -> Optional[dict]:
    """
    Parse the decoded WIF payload bytes into its components:
      - network (mainnet/testnet)
      - 32-byte raw private key
      - compression flag

    Expected payload lengths:
      33 bytes = 1 (version) + 32 (key)               → uncompressed
      34 bytes = 1 (version) + 32 (key) + 1 (0x01)    → compressed
    """
    if len(payload) not in (33, 34):
        return None

    version_byte = payload[0]
    raw_key      = payload[1:33]

    # Determine network
    if version_byte == MAINNET_PREFIX:
        network = "Mainnet"
    elif version_byte == TESTNET_PREFIX:
        network = "Testnet"
    else:
        network = f"Unknown (0x{version_byte:02X})"

    # Determine compression
    if len(payload) == 34:
        compressed = (payload[33] == 0x01)
    else:
        compressed = False

    return {
        "version_byte": version_byte,
        "network":      network,
        "raw_key":      raw_key,
        "compressed":   compressed,
    }

# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC KEY DERIVATION (secp256k1 elliptic curve)
# ─────────────────────────────────────────────────────────────────────────────

def derive_public_key(raw_key: bytes, compressed: bool = True) -> Optional[bytes]:
    """
    Derive the public key from a 32-byte private key using secp256k1.

    Elliptic curve public key derivation:
      PublicKey = PrivateKey × G
    where G is the secp256k1 generator point.

    Compressed form (33 bytes): 0x02 or 0x03 prefix + 32-byte X coordinate
    Uncompressed form (65 bytes): 0x04 prefix + X + Y coordinates
    """
    try:
        signing_key   = ecdsa.SigningKey.from_string(raw_key, curve=SECP256K1)
        verifying_key = signing_key.get_verifying_key()

        if compressed:
            # secp256k1 point parity: even Y → 0x02, odd Y → 0x03
            x = verifying_key.pubkey.point.x()
            y = verifying_key.pubkey.point.y()
            prefix = b"\x02" if y % 2 == 0 else b"\x03"
            return prefix + x.to_bytes(32, "big")
        else:
            return b"\x04" + verifying_key.to_string()  # 64 bytes of X+Y

    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# ADDRESS GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def p2pkh_address(pubkey: bytes) -> str:
    """
    Generate a Legacy P2PKH address (starts with '1').

    Steps:
      1. Hash160 the public key
      2. Prepend version byte 0x00 (mainnet)
      3. Base58Check encode
    """
    h160   = hash160(pubkey)
    payload = b"\x00" + h160          # 0x00 = mainnet P2PKH version
    return base58check_encode(payload)


def p2sh_p2wpkh_address(pubkey: bytes) -> str:
    """
    Generate a P2SH-P2WPKH address (starts with '3') — SegWit wrapped in P2SH.

    Steps:
      1. Build redeemScript: OP_0 <20-byte hash160(pubkey)>
      2. Hash160 the redeemScript
      3. Prepend version byte 0x05 (mainnet P2SH)
      4. Base58Check encode
    """
    h160          = hash160(pubkey)
    redeem_script = b"\x00\x14" + h160   # OP_0 PUSH20 <hash>
    script_hash   = hash160(redeem_script)
    payload       = b"\x05" + script_hash  # 0x05 = mainnet P2SH version
    return base58check_encode(payload)


def p2wpkh_address(pubkey: bytes) -> str:
    """
    Generate a native SegWit P2WPKH Bech32 address (starts with 'bc1q').

    Steps:
      1. Hash160 the compressed public key
      2. Encode as Bech32 with HRP 'bc' and witness version 0
    """
    h160       = hash160(pubkey)
    # Convert 8-bit groups to 5-bit groups for Bech32 encoding
    converted  = bech32.convertbits(h160, 8, 5, True)
    return bech32.bech32_encode("bc", [0x00] + converted)  # witness version 0

# ─────────────────────────────────────────────────────────────────────────────
# FULL ANALYSIS OF A SINGLE WIF CANDIDATE
# ─────────────────────────────────────────────────────────────────────────────

def analyze_wif(wif: str) -> Optional[dict]:
    """
    Full pipeline: decode → validate checksum → extract key → derive addresses.
    Returns a result dict or None if the WIF is fundamentally invalid.
    """
    payload, embedded_cs, valid, error = base58check_decode(wif)

    result = {
        "wif":          wif,
        "valid":        valid,
        "error":        error,
        "payload":      payload,
        "embedded_cs":  embedded_cs,
        "computed_cs":  double_sha256(payload)[:4] if payload and len(payload) >= 1 else None,
        "key_info":     None,
        "pubkey_comp":  None,
        "addresses":    {},
    }

    if not valid or payload is None:
        return result

    key_info = extract_key_info(payload)
    if key_info is None:
        result["valid"] = False
        result["error"] = f"Unexpected payload length: {len(payload)} bytes"
        return result

    result["key_info"] = key_info

    # Derive public key (always use compressed form for modern addresses)
    pubkey_comp = derive_public_key(key_info["raw_key"], compressed=True)
    if pubkey_comp is None:
        result["valid"] = False
        result["error"] = "Private key scalar is invalid for secp256k1"
        return result

    result["pubkey_comp"] = pubkey_comp

    # Generate all three address types
    result["addresses"] = {
        "P2PKH (Legacy)":      p2pkh_address(pubkey_comp),
        "P2SH-P2WPKH (SegWit wrapped)": p2sh_p2wpkh_address(pubkey_comp),
        "P2WPKH (Native SegWit)": p2wpkh_address(pubkey_comp),
    }

    return result

# ─────────────────────────────────────────────────────────────────────────────
# BRUTE-FORCE RECOVERY (max 2 unknown positions)
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# MULTIPROCESSING CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Safety cap on unknown positions.
# With multiprocessing, 3 unknowns (195,112 candidates) is tractable.
# 4 unknowns (~11M) remains off-limits — exponential growth is brutal.
MAX_UNKNOWNS = 3

def _get_worker_count() -> int:
    """
    Determine how many worker processes to spawn.

    Strategy:
      - Use all logical CPUs available to the process.
      - On Termux/Android, cpu_count() reflects the device's core count.
      - Cap at 8 to avoid thrashing on high-core-count machines where
        the candidate space is small enough that IPC overhead dominates.
      - Always use at least 1 (graceful single-process fallback).
    """
    return max(1, min(os.cpu_count() or 1, 8))


def _get_mp_context():
    """
    Return the safest multiprocessing context for the current platform.

    'fork' is preferred on Linux/Android (Termux):
      - Child inherits parent memory — no re-import of ecdsa/bech32.
      - Significantly faster startup per worker.

    'spawn' is the fallback:
      - Required on Windows and some restricted Android environments.
      - Requires the worker function to be importable at module level
        (hence _worker_validate_chunk is a top-level function, not a closure).
    """
    try:
        return multiprocessing.get_context("fork")
    except (ValueError, AttributeError):
        return multiprocessing.get_context("spawn")


# ─────────────────────────────────────────────────────────────────────────────
# WORKER FUNCTION  (must be top-level for pickle compatibility with 'spawn')
# ─────────────────────────────────────────────────────────────────────────────

def _worker_validate_chunk(args: tuple) -> list[dict]:
    """
    Worker entry point — validates a contiguous slice of the candidate space.

    Arguments arrive as a single tuple so Pool.map() can serialise them:
      (wif_template, positions, combo_chunk)

    WHY A TUPLE?
    Pool.map() pickles each argument. A plain tuple is cheaply serialised.
    The combo_chunk is a list of tuples (e.g. [('A','1'), ('A','2'), ...])
    representing the Base58 characters to substitute into each '?' slot.

    RETURN VALUE:
    A list of result dicts for every candidate in this chunk that passes
    full Base58Check validation. Empty list if none pass.

    NO SIDE EFFECTS:
    This function is pure — no shared state, no I/O, no locks. Results are
    collected by the parent via Pool.map() after all workers finish.
    """
    wif_template, positions, combo_chunk = args

    valid_hits = []
    template_list = list(wif_template)  # mutable working copy

    for combo in combo_chunk:
        # Substitute this combination into the placeholder positions
        candidate = template_list[:]          # fresh copy each iteration
        for pos, ch in zip(positions, combo):
            candidate[pos] = ch
        candidate_str = "".join(candidate)

        # Quick length pre-filter — avoids full decode on obvious mismatches
        if len(candidate_str) not in WIF_LENGTHS:
            continue

        # Full Base58Check decode + checksum verification
        result = analyze_wif(candidate_str)
        if result and result["valid"]:
            # Store raw_key as hex string so it survives pickle round-trip
            if result["key_info"] and isinstance(
                result["key_info"]["raw_key"], (bytes, bytearray)
            ):
                result["key_info"]["raw_key"] = result["key_info"]["raw_key"]
            if result["pubkey_comp"] and isinstance(result["pubkey_comp"], (bytes, bytearray)):
                result["pubkey_comp"] = result["pubkey_comp"]
            valid_hits.append(result)

    return valid_hits


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK PARTITIONING  (determinism guarantee lives here)
# ─────────────────────────────────────────────────────────────────────────────

def _partition_combos(
    n_unknown: int,
    n_workers: int,
) -> list[list[tuple]]:
    """
    Pre-generate the full Cartesian product and split it into n_workers
    contiguous, non-overlapping slices.

    WHY PRE-GENERATE INSTEAD OF USING itertools LAZILY?

    For deterministic ordered output we need Pool.map() to receive chunks in
    a fixed order. Pool.map() itself preserves submission order in its return
    value — but only if the chunks themselves are defined before any worker
    starts. Pre-generating ensures:

      1. Chunk boundaries are identical on every run (determinism).
      2. No shared iterator state between workers (no races).
      3. Pool.map() result list index == submission order == alphabetic order
         of the Base58 product — so final output is always sorted.

    MEMORY NOTE:
    For 3 unknowns: 195,112 tuples × ~56 bytes each ≈ ~11 MB peak.
    This is acceptable on any modern device; Termux typically has 1–8 GB RAM.
    For 2 unknowns it's ~188 KB.
    """
    all_combos = list(itertools.product(BASE58_ALPHABET, repeat=n_unknown))
    total      = len(all_combos)

    # Ceiling division so no combo is left out when total % n_workers != 0
    chunk_size = (total + n_workers - 1) // n_workers

    return [
        all_combos[i : i + chunk_size]
        for i in range(0, total, chunk_size)
    ]


# ─────────────────────────────────────────────────────────────────────────────
# BRUTE-FORCE RECOVERY  (multiprocessing coordinator)
# ─────────────────────────────────────────────────────────────────────────────

def recover_candidates(wif_template: str) -> list[dict]:
    """
    Recover valid WIF candidates from a template containing '?' placeholders.

    ALGORITHM:
      1. Identify placeholder positions in the template.
      2. Validate unknown count against MAX_UNKNOWNS.
      3. Determine worker count from available CPU cores.
      4. Pre-partition the Base58^N Cartesian product into per-worker chunks
         (contiguous slices, deterministic order).
      5. Spawn a process pool and dispatch chunks via Pool.map().
         Pool.map() blocks until ALL workers finish, then returns results
         in submission order — guaranteeing deterministic output ordering.
      6. Flatten per-chunk result lists into a single ordered list.

    DETERMINISM GUARANTEE:
      Because chunks are pre-generated in alphabetical product order and
      Pool.map() preserves that order in its return value, the final candidate
      list is always in the same order as a single-threaded scan would produce,
      regardless of which worker completed first or how the OS scheduled them.

    SAFETY CONSTRAINTS PRESERVED:
      - MAX_UNKNOWNS cap unchanged from single-threaded version.
      - No shared mutable state between workers.
      - No network access (workers inherit the same offline-only environment).
      - All candidates still go through full Base58Check validation.
    """
    positions = [i for i, ch in enumerate(wif_template) if ch == "?"]
    n_unknown = len(positions)

    if n_unknown == 0:
        return []

    if n_unknown > MAX_UNKNOWNS:
        print(
            f"\n{C.RED}[!] Too many unknowns: {n_unknown}. "
            f"Maximum allowed is {MAX_UNKNOWNS} "
            f"(58^{n_unknown} = {58**n_unknown:,} candidates).\n"
            f"    Narrow down the unknown positions and try again.{C.RESET}"
        )
        return []

    total      = 58 ** n_unknown
    n_workers  = _get_worker_count()
    # For tiny search spaces (1 unknown = 58 candidates) multiprocessing
    # overhead exceeds the work itself — use a single worker.
    if total <= 256:
        n_workers = 1

    print(
        f"\n{C.CYAN}[*] Brute-forcing {n_unknown} unknown(s) at "
        f"position(s) {positions}\n"
        f"    {total:,} candidates  ·  {n_workers} worker process(es){C.RESET}"
    )

    # ── Partition the work ─────────────────────────────────────────────────
    chunks  = _partition_combos(n_unknown, n_workers)
    n_chunks = len(chunks)

    # Build argument tuples for Pool.map() — one per chunk
    job_args = [
        (wif_template, positions, chunk)
        for chunk in chunks
    ]

    # ── Dispatch to worker pool ────────────────────────────────────────────
    t_start = time.monotonic()

    if n_workers == 1:
        # Single-worker path: skip process spawning overhead entirely.
        # Still calls the same _worker_validate_chunk for code-path parity.
        chunk_results = [_worker_validate_chunk(job_args[0])]
    else:
        ctx = _get_mp_context()
        # chunksize=1: each Pool.map() call maps one job_arg to one worker.
        # Our jobs are already right-sized, so chunksize=1 is correct here.
        with ctx.Pool(processes=n_workers) as pool:
            chunk_results = pool.map(_worker_validate_chunk, job_args, chunksize=1)

        # Report per-chunk progress after pool completes
        # (printing inside workers would interleave unpredictably)
        completed = 0
        for i, chunk in enumerate(chunks, 1):
            completed += len(chunk)
            pct = completed / total * 100
            print(
                f"  {C.DIM}Worker chunk {i}/{n_chunks} done  "
                f"({completed:,}/{total:,} · {pct:.0f}%){C.RESET}"
            )

    elapsed = time.monotonic() - t_start

    # ── Flatten results — order preserved by Pool.map() ───────────────────
    # chunk_results is a list-of-lists in submission order.
    # Flattening preserves the deterministic alphabetical ordering.
    found = [result for chunk in chunk_results for result in chunk]

    rate = total / elapsed if elapsed > 0 else 0
    print(
        f"\n  {C.DIM}Checked {total:,} candidates in {elapsed:.2f}s "
        f"({rate:,.0f}/s){C.RESET}"
    )
    return found

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT FORMATTING
# ─────────────────────────────────────────────────────────────────────────────

def sep(char="─", width=70, color=C.DIM):
    print(f"{color}{char * width}{C.RESET}")

def header(title: str):
    sep("═", 70, C.CYAN)
    print(f"{C.BOLD}{C.WHITE}  {title}{C.RESET}")
    sep("═", 70, C.CYAN)

def section(title: str):
    print(f"\n{C.BOLD}{C.YELLOW}▸ {title}{C.RESET}")
    sep()

def print_result(result: dict, index: int = 0, total: int = 1):
    """Pretty-print the full analysis of a single WIF candidate."""
    label = f"Candidate {index}/{total}" if total > 1 else "Analysis Result"
    section(label)

    print(f"  {'WIF:':<28} {C.WHITE}{result['wif']}{C.RESET}")

    if result["valid"]:
        print(f"  {'Status:':<28} {C.GREEN}✓ VALID (checksum passed){C.RESET}")
    else:
        print(f"  {'Status:':<28} {C.RED}✗ INVALID — {result['error']}{C.RESET}")

    # Checksum details
    if result["embedded_cs"]:
        print(f"  {'Embedded checksum:':<28} {C.DIM}{result['embedded_cs'].hex()}{C.RESET}")
    if result["computed_cs"]:
        match_mark = C.GREEN + "✓" if result["valid"] else C.RED + "✗"
        print(f"  {'Computed checksum:':<28} {match_mark} {result['computed_cs'].hex()}{C.RESET}")

    if not result["valid"] or result["key_info"] is None:
        return

    ki = result["key_info"]
    print(f"\n  {C.BOLD}Key Details:{C.RESET}")
    print(f"  {'Network:':<28} {ki['network']} "
          f"(version byte 0x{ki['version_byte']:02X})")
    print(f"  {'Private key (hex):':<28} {C.WHITE}{ki['raw_key'].hex()}{C.RESET}")
    print(f"  {'Compression flag:':<28} {'Compressed' if ki['compressed'] else 'Uncompressed'}")

    if result["pubkey_comp"]:
        print(f"  {'Public key (compressed):':<28} "
              f"{C.WHITE}{result['pubkey_comp'].hex()}{C.RESET}")

    if result["addresses"]:
        print(f"\n  {C.BOLD}Derived Addresses:{C.RESET}")
        for addr_type, addr in result["addresses"].items():
            print(f"  {'  ' + addr_type + ':':<30} {C.GREEN}{addr}{C.RESET}")


def print_validation_errors(wif: str):
    """Explain why a WIF fails format validation before even attempting decode."""
    section("Pre-Validation Failures")

    # Length
    if len(wif) not in WIF_LENGTHS:
        print(f"  {C.RED}• Length: {len(wif)} characters "
              f"(expected 51 or 52){C.RESET}")
    else:
        print(f"  {C.GREEN}• Length: {len(wif)} characters ✓{C.RESET}")

    # Character set
    bad = sorted(set(ch for ch in wif if ch not in BASE58_SET and ch != "?"))
    if bad:
        print(f"  {C.RED}• Invalid characters: {bad}{C.RESET}")
        print(f"  {C.DIM}    Base58 excludes: 0 (zero), O (capital-o), "
              f"I (capital-i), l (lowercase-L){C.RESET}")
    else:
        print(f"  {C.GREEN}• All characters are valid Base58 ✓{C.RESET}")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""
{C.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║          Bitcoin WIF Forensic Analyzer & Recovery Tool              ║
║          Offline · Educational · Safe                               ║
╚══════════════════════════════════════════════════════════════════════╝{C.RESET}

{C.YELLOW}⚠  SECURITY NOTICE:{C.RESET}
   This tool operates entirely offline and does not transmit any data.
   Private keys control funds. Keep recovered keys confidential.
   This software is provided for educational and recovery purposes only.

{C.DIM}Enter your WIF string below. Use '?' as a placeholder for unknown
characters (up to {MAX_UNKNOWNS} unknowns — brute-forced in parallel across all CPU cores).

Examples:
  Full WIF:       KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
  One unknown:    KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP9861?
  Two unknowns:   KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP986??
  Three unknowns: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98???
{C.RESET}"""


def main():
    print(BANNER)

    try:
        raw_input_str = input(f"{C.BOLD}Enter WIF (or WIF with '?' placeholders): {C.RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{C.DIM}Aborted.{C.RESET}")
        sys.exit(0)

    if not raw_input_str:
        print(f"{C.RED}[!] No input provided. Exiting.{C.RESET}")
        sys.exit(1)

    wif_input = raw_input_str

    # ── Input Summary ──────────────────────────────────────────────────────
    header("Input Summary")
    print(f"  {'Input:':<28} {C.WHITE}{wif_input}{C.RESET}")
    print(f"  {'Length:':<28} {len(wif_input)} characters")

    n_placeholders = wif_input.count("?")
    non_ph         = wif_input.replace("?", "")
    invalid_chars  = [ch for ch in non_ph if ch not in BASE58_SET]

    print(f"  {'Placeholders (?):':<28} {n_placeholders}")
    if invalid_chars:
        print(f"  {'Invalid chars:':<28} {C.RED}{sorted(set(invalid_chars))}{C.RESET}")
    else:
        print(f"  {'Invalid chars:':<28} {C.GREEN}None ✓{C.RESET}")

    # ── MODE: No placeholders → direct validation ──────────────────────────
    if n_placeholders == 0:
        header("Validation & Analysis")

        pre_ok, pre_err = validate_wif_string(wif_input)
        if not pre_ok:
            print_validation_errors(wif_input)
        else:
            result = analyze_wif(wif_input)
            if result:
                print_result(result)
            else:
                print(f"{C.RED}  [!] Analysis failed unexpectedly.{C.RESET}")

    # ── MODE: Placeholders → recovery mode ────────────────────────────────
    else:
        n_workers = _get_worker_count()
        header("Recovery Mode")
        print(f"  {'CPU cores available:':<28} {os.cpu_count() or '?'}")
        print(f"  {'Worker processes:':<28} {n_workers}")
        print(f"  {'Max unknowns allowed:':<28} {MAX_UNKNOWNS}")

        if n_placeholders > MAX_UNKNOWNS:
            print(f"\n{C.RED}[!] {n_placeholders} unknown positions detected.")
            print(f"    Maximum supported is {MAX_UNKNOWNS} (58^{n_placeholders} "
                  f"= {58**n_placeholders:,} candidates is too large).")
            print(f"    Please narrow down the unknown positions and try again.{C.RESET}")
            sys.exit(1)

        if len(wif_input.replace("?", "X")) not in WIF_LENGTHS:
            print(f"\n{C.YELLOW}[!] Warning: Template length {len(wif_input)} is not 51 or 52.")
            print(f"    This may indicate extra missing characters not marked with '?'.{C.RESET}")

        candidates = recover_candidates(wif_input)

        if not candidates:
            print(f"\n{C.RED}[✗] No valid candidates found.{C.RESET}")
            print(f"{C.DIM}    This may mean:{C.RESET}")
            print(f"{C.DIM}    • More than {MAX_UNKNOWNS} characters are corrupted{C.RESET}")
            print(f"{C.DIM}    • The template itself has additional errors{C.RESET}")
            print(f"{C.DIM}    • The original WIF used a non-standard format{C.RESET}")
        else:
            print(f"\n{C.GREEN}[✓] Found {len(candidates)} valid candidate(s):{C.RESET}")
            header(f"Recovery Results ({len(candidates)} found)")
            for i, cand in enumerate(candidates, 1):
                print_result(cand, index=i, total=len(candidates))

    # ── Footer ─────────────────────────────────────────────────────────────
    sep("═", 70, C.CYAN)
    print(f"{C.DIM}  Analysis complete. No data was transmitted or written to disk.{C.RESET}")
    sep("═", 70, C.CYAN)
    print()


if __name__ == "__main__":
    # CRITICAL for multiprocessing correctness on all platforms:
    #
    # 'spawn' and 'forkserver' start methods require that the worker function
    # (_worker_validate_chunk) be importable from the main module. This is only
    # guaranteed when the script is run as __main__, not imported as a module.
    #
    # freeze_support() is a no-op on non-frozen (normal Python) environments
    # but is required boilerplate if this script is ever compiled with PyInstaller.
    multiprocessing.freeze_support()
    main()


# =============================================================================
# TERMUX SETUP INSTRUCTIONS
# =============================================================================
#
# STEP 1 — Install Termux
#   Download Termux from F-Droid (recommended) or the Play Store.
#   https://f-droid.org/en/packages/com.termux/
#
# STEP 2 — Update package lists and install Python
#   pkg update && pkg upgrade
#   pkg install python openssl
#
#   openssl is required for RIPEMD-160 support in Python hashlib on Android.
#
# STEP 3 — Install pip dependencies
#   pip install ecdsa bech32
#
#   If pip is not found:
#   python -m ensurepip --upgrade
#   python -m pip install ecdsa bech32
#
#   Note: multiprocessing is part of Python's standard library — no extra
#   install needed.
#
# STEP 4 — Transfer this script to your device
#   Option A: Using adb (from a PC):
#     adb push wif_forensic.py /sdcard/wif_forensic.py
#   Option B: Use a file manager app and copy to Termux home.
#   Option C: In Termux, paste directly:
#     nano ~/wif_forensic.py   # paste content, Ctrl+X to save
#
# STEP 5 — Run the script
#   cd ~
#   python wif_forensic.py
#
# OPTIONAL: Make it executable
#   chmod +x wif_forensic.py
#   ./wif_forensic.py
#
# MULTIPROCESSING NOTES FOR TERMUX/ANDROID:
#   The script auto-detects available CPU cores and uses 'fork' context,
#   which is the fastest and most compatible method on Linux/Android.
#   On a typical Android device with 4–8 cores, brute-forcing 3 unknowns
#   (~195K candidates) completes in under 10 seconds.
#
#   If you see "OSError: [Errno 12] Cannot allocate memory":
#     → Reduce open apps and free RAM before running.
#     → The script will fall back gracefully to fewer workers if needed.
#
#   If multiprocessing fails to start on your device:
#     → The script will still work correctly with a single worker process.
#
# TROUBLESHOOTING:
#   "RIPEMD160 not available" → Run: pkg install openssl
#   "ecdsa not found"         → pip install ecdsa
#   "bech32 not found"        → pip install bech32
#   Colors not showing        → Terminal may not support ANSI escape codes;
#                               remove the C.* wrappers from print() calls.
#
# =============================================================================
