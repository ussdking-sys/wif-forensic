# SECURITY.md — Private Key Security Guidance

> This document explains how to handle Bitcoin private keys safely when using WIF Forensic or any key recovery tool. It is written for users at all experience levels.

---

## 🔴 The Fundamental Rule

**A Bitcoin private key is not a password. It cannot be reset, recovered by a support team, or changed without moving your funds to a new wallet.**

Whoever holds the private key controls the funds. There are no exceptions.

---

## Before You Run This Tool

### 1. Disconnect from the Internet

This is the single most important step.

**On Android (Termux):**
- Swipe down the notification shade → tap Wi-Fi icon to disable
- Swipe down → tap Mobile Data icon to disable
- Enable Airplane Mode for complete certainty, then re-enable Bluetooth/NFC only if needed

**On Linux / macOS:**
```bash
# Verify you have no active connections before running
nmcli networking off        # NetworkManager (most Linux distros)
# or
sudo ifconfig eth0 down     # Wired
sudo ifconfig wlan0 down    # Wireless
```

**On Windows:**
- Settings → Network & Internet → toggle off Wi-Fi and Ethernet

**Why this matters:** Even if this tool makes no network calls (it does not — you can verify by reading the source), a connected device running any tool that displays a private key is a risk. Screen capture malware, clipboard sniffers, and keyloggers operate independently of what the tool itself does.

---

### 2. Check Your Environment

Before entering a private key into any tool, ask yourself:

| Question | Safe answer | Dangerous answer |
|---|---|---|
| Is the device connected to the internet? | No | Yes |
| Is anyone watching your screen? | No | Yes |
| Is the tool running in a cloud shell or remote session? | No | Yes |
| Is the device shared with others? | No | Yes |
| Is screen recording software active? | No | Yes |
| Is the device syncing screenshots to a cloud account? | No | Yes |

If any answer is in the "Dangerous" column, stop and resolve it first.

---

### 3. Disable Cloud Sync for Screenshots and Clipboard

On many Android devices, screenshots automatically upload to Google Photos. If you ever screenshot a terminal showing a private key, that key is now on Google's servers.

- **Google Photos:** Settings → Back up → turn off "Backup"
- **Samsung Cloud:** Settings → Accounts → Samsung Cloud → turn off Gallery sync

Clipboard managers and sync apps (like GBoard's clipboard history or Microsoft SwiftKey) may also retain clipboard contents and sync them to the cloud. Avoid copying private keys to the clipboard entirely.

---

## While Running This Tool

### Do Not Share the Output

The output of this tool — specifically the `Private key (hex)` and `WIF` fields — must never be:

- Pasted into a chat message (Telegram, WhatsApp, Signal, Discord, iMessage)
- Emailed to yourself or anyone else
- Uploaded to any website for "verification"
- Posted as a forum question, even with "just the first few characters"
- Entered into any other tool or website
- Photographed with another device

**There is no legitimate reason for any person or service to ask you to share your private key.** If someone claims they need it to help you, they are attempting to steal your funds.

---

### Do Not Let the Terminal Scroll into a Log

Some terminal emulators save scrollback history to disk. If your terminal has a large scrollback buffer, the private key may persist in `~/.bash_history` or in the terminal's session log even after you close it.

```bash
# After finishing, clear Termux's scrollback
# Ctrl+L  (clears visible screen)
# Then exit and re-open Termux to clear scrollback buffer

# Also clear shell history
history -c && history -w
```

---

## After Running This Tool

### 1. Immediately Import the Recovered Key to Cold Storage

Once you have a valid, confirmed key:

1. **Import it directly into a hardware wallet or fully-offline software wallet** — do not store the WIF string as plaintext anywhere
2. **Verify the address match** — confirm the addresses shown by this tool match what your original wallet showed
3. **Move funds to a freshly generated address** — a recovered key that was at any point at risk should be considered compromised; generate a new wallet and sweep funds to it

---

### 2. Securely Erase Any Temporary Notes

If you wrote the WIF on paper during this process:

- Use a shredder, not a recycling bin
- Do not photograph the paper
- Do not enter the handwritten key into any cloud note app (Google Keep, Apple Notes, Notion, Evernote)

---

### 3. After Recovery, Revoke the Old Key's Authority

The safest course after recovering a private key that was at any point in an insecure state:

1. Open your wallet with the recovered key
2. Generate a completely new wallet address (new private key, never exposed)
3. Send all funds from the recovered address to the new address
4. Consider the recovered key permanently retired

This is called **key rotation** and is the conservative, correct approach when there is any doubt about whether a private key was exposed.

---

## Common Mistakes That Lead to Key Exposure

| Mistake | Why it's dangerous |
|---|---|
| Asking for help on Reddit/Discord with your WIF | Even partial keys can narrow the search space dramatically |
| Storing the WIF in a notes app that syncs to cloud | Dropbox, iCloud, Google Drive all have server-side access |
| Running a key tool over SSH on a remote server | The remote server's admin can see everything |
| Using a "WIF validator" website | That site receives and logs your key the moment you submit |
| Copying WIF to clipboard on a phone | Clipboard contents are accessible to any app with clipboard permission |
| Taking a photo of the terminal output | EXIF data and cloud sync can expose it |
| Using a shared or work computer | Other users, IT departments, and MDM software may have access |

---

## On Trust and Open Source

This tool is open-source for one reason: **so you can verify it does exactly what it claims.**

Before running any key recovery tool, including this one:

1. Read the import statements — check for `socket`, `urllib`, `requests`, `httpx`, or any other networking library
2. Check for file write operations — `open(..., 'w')`, `os.write`, logging to files
3. Run `python -m trace --trace wif_forensic.py` to see every line that executes
4. If you are not comfortable reading Python, ask a trusted technical person to review it before running

**"Trust, but verify" is not enough for private key security. Verify first. Trust after.**

---

## Threat Model Summary

| Threat | Mitigated by this tool? | Your responsibility |
|---|---|---|
| Tool exfiltrating key over network | ✅ Yes — no network code | Verify by reading imports |
| Tool writing key to disk | ✅ Yes — no file writes | Verify by reading source |
| Screen capture malware | ❌ No | Run on a clean, offline device |
| Clipboard sniffing | ❌ No | Do not copy key to clipboard |
| Physical shoulder surfing | ❌ No | Run in a private location |
| Cloud sync of screenshots | ❌ No | Disable before running |
| Compromised terminal/shell | ❌ No | Use a minimal, trusted environment |
| Social engineering (asking you to share the key) | ❌ No | Never share with anyone |
