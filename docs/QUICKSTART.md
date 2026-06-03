# QUICKSTART — Get Running in 2 Minutes

> **For experienced users who just want to run the tool. For detailed explanations, see README.md.**

---

## ⚡ TL;DR

```bash
# Install dependencies (one time)
pip install ecdsa bech32

# Run the tool
python wif_forensic.py

# Enter a WIF (use ? for unknown characters)
Enter WIF: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617

# Get back valid addresses
```

---

## Installation — Choose Your Platform

### Android (Termux) — Recommended

```bash
# 1. Get Termux from F-Droid (NOT Play Store)
# 2. In Termux:

pkg update && pkg install python openssl
pip install ecdsa bech32

# 3. Copy the script
nano ~/wif_forensic.py
# (paste the content, Ctrl+X → Y → Enter)

# 4. Run
python ~/wif_forensic.py
```

**Before running:** Go offline. Disable Wi-Fi and cellular.

---

### Linux / macOS

```bash
python3 -m pip install --user ecdsa bech32
python3 wif_forensic.py
```

---

### Windows

```cmd
pip install ecdsa bech32
python wif_forensic.py
```

---

## Usage — Three Scenarios

### Scenario 1: Verify a Complete WIF

```
Enter WIF: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617

Output:
  Status: ✓ VALID (checksum passed)
  Network: Mainnet
  P2PKH (Legacy):      1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK
  P2SH-P2WPKH (SegWit): 3D9iyFHi1Zs9KoyynUfrL82rGhJfYTfSG4
  P2WPKH (Native SegWit): bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd
```

✓ **When to use:** You have a complete WIF and want to verify it's uncorrupted.

---

### Scenario 2: Recover 1–2 Unknown Characters

```
Enter WIF: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP986??

Output:
  [*] Brute-forcing 2 unknown(s)
      3,364 candidates  ·  4 worker processes
  ...
  Checked 3,364 candidates in 0.18s
  [✓] Found 1 valid candidate(s):
    WIF: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
```

✓ **When to use:** You have a WIF written on paper and 1–3 characters are smudged/unreadable.

---

### Scenario 3: Diagnose Why a WIF Fails

```
Enter WIF: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP980000

Output:
  [✗] INVALID — Checksum mismatch
  Embedded checksum: a62019d2
  Computed checksum: fb3a8c11
```

✗ **What to do:** More than 3 characters are corrupted. Try marking more positions as `?`, or verify you transcribed the known characters correctly (especially `0/O`, `I/l`, `5/S`, `8/B`).

---

## Understanding the Output

| Field | Means |
|---|---|
| `Status: ✓ VALID` | Checksum matched — key is intact |
| `Status: ✗ INVALID` | Checksum mismatch, wrong length, or bad characters |
| `Network: Mainnet` | Real Bitcoin network (version byte `0x80`) |
| `Network: Testnet` | Test network (version byte `0xEF`) |
| `P2PKH (Legacy)` | Address starting with `1` — oldest format |
| `P2SH-P2WPKH` | Address starting with `3` — SegWit wrapped |
| `P2WPKH (Native SegWit)` | Address starting with `bc1q` — lowest fees |

---

## Common Mistakes

| Mistake | Fix |
|---|---|
| "ModuleNotFoundError: ecdsa" | Run: `pip install ecdsa` |
| "No module named bech32" | Run: `pip install bech32` |
| "RIPEMD160 not available" | Run: `pkg install openssl` (Termux only) |
| Entered a WIF but nothing happened | Press Enter after pasting the string |
| Tool found 0 candidates | More than 3 characters are corrupted; mark more positions as `?` |
| The recovered key doesn't match my known addresses | Double-check the known characters, especially `0/O`, `I/l/1`, `5/S`, `8/B` |

---

## Next Steps After Recovery

1. **Verify the addresses** — confirm the three addresses shown match your original wallet
2. **Import to hardware wallet** — move the recovered WIF directly to a Ledger, Trezor, or air-gapped software wallet
3. **Don't linger with the WIF** — do not keep it in terminal, notes apps, or screenshots
4. **Sweep funds** — send all Bitcoin from the recovered address to a freshly generated one

---

## Detailed Docs

- **../README.md** — Full documentation, blockchain glossary, use cases
- **../SECURITY.md** — Extended security guidance for private keys
- **HOW_IT_WORKS.md** — Algorithm deep-dive for developers
- **GLOSSARY.md** — Technical term reference (standalone)

---

## Key Facts

- ✅ **100% offline** — no network calls, no data transmission
- ✅ **Open source** — read the code to verify it
- ✅ **Multiprocessing** — uses all CPU cores for fast brute-force
- ✅ **Deterministic** — same input always produces same output
- ⚠️ **Max 3 unknowns** — safety cap; 4+ unknowns not supported
- ⚠️ **Your responsibility** — secure any recovered keys immediately

---

## Need Help?

1. **Read SECURITY.md** — covers private key handling best practices
2. **Check troubleshooting in README.md** — common issues and solutions
3. **Read the source** — it's extensively commented

Remember: **This tool only reveals information already in your WIF. It cannot create funds, sign transactions, or access the network.**
