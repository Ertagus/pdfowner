# pdfowner.py

📦 **Repository:** https://github.com/Ertagus/pdfowner
🇮🇹 [Versione italiana](README_it.md)

Extract and crack the **owner password** (the edit/permissions password) of a PDF in a single pass: it reads the hash from the file, then runs a multi-core dictionary attack against it.

Useful for PDFs that open without a password but block editing, printing or copying.

---

## Requirements

- **Python 3.8+**
- **pyhanko** — hash extraction from the PDF (required)
- **pycryptodome** — RC4 in C, ~2× faster (optional, there is a pure-Python fallback)

Dependencies are **installed automatically** on first run if missing. To install them by hand:

```
python -m pip install pyhanko pycryptodome
```

---

## Usage

```
python pdfowner.py <file.pdf> [wordlist.txt] [options]
```

### Drag & drop (Windows)

The quickest way: **drag a PDF onto the `pdfowner.py` icon**. It runs on its own, with no wordlist (uses/downloads rockyou.txt), and stays open at the end thanks to the final "press any key" pause.

One-time prerequisite: associate `.py` files with Python.
- Right-click a `.py` → *Open with* → *Choose another app* → Python → *Always*.
- Or from an admin prompt:
  ```
  assoc .py=Python.File
  ftype Python.File="C:\path\to\python.exe" "%1" %*
  ```
  (the trailing `%*` forwards arguments, including the dropped PDF)

On the **first run** it auto-installs pyhanko + pycryptodome and downloads rockyou.txt; on later runs it starts directly.

### Options

| Flag | Description |
|------|-------------|
| `-u`, `--user-pw PW` | Cleartext open password, if the PDF also has one for opening (default: empty) |
| `-c`, `--cores N` | Number of cores to use (default: all) |
| `--no-install` | Do not install missing deps nor download the wordlist; exit with instructions |
| `--selftest` | Verify the algorithm against known test vectors, then exit |

Run with no arguments to print the full help.

### Automatic wordlist

If you **don't** pass a wordlist:

1. it looks for `rockyou.txt` in the current folder (then in the script's folder);
2. if absent, it **downloads it** from GitHub (~140 MB) with a progress bar.

With `--no-install` the download is disabled: if the wordlist is missing, it exits with instructions.

### Colored output

Each phase is color-coded: `::` phase, `->` info, `OK` green, `!!` yellow (warning), `XX` red (error). E.g. missing dependency → installing, missing wordlist → downloading, etc. On Windows colors are enabled automatically (VT mode).

### Examples

```
# base crack: no wordlist -> use/download rockyou.txt, all cores
python pdfowner.py document.pdf

# explicit wordlist
python pdfowner.py document.pdf rockyou.txt

# limit to 4 cores
python pdfowner.py document.pdf rockyou.txt -c 4

# PDF that also has a known open password
python pdfowner.py document.pdf rockyou.txt -u "openPW"

# locked-down environment, no auto-install
python pdfowner.py document.pdf rockyou.txt --no-install

# verify the algorithm is correct
python pdfowner.py --selftest
```

### Output

```
=== pdfowner.py ===  RC4=C  cores=8
:: Extracting owner hash
  OK R4  keylen=128  (AES-128)
     $pdfo$4*4*128*32*<owner-hash>*0*
:: Wordlist
  OK found rockyou.txt
:: Crack
  -> 400000/14344391  14328 pw/s

[+] OWNER PASSWORD: <password>  (39s)
```

The `$pdfo$...` line is the extracted hash: reusable with the patched John the Ripper build (Didier Stevens' `$pdfo$` format), if you prefer.

---

## Wordlist

`rockyou.txt` (~140 MB, 14M passwords) is the standard starting point:
- `naive-hashcat` release on GitHub
- or the SecLists package

Put the file in the same folder, or pass the full path.

---

## Limitations

- **RC4 only (revisions R2 / R3 / R4)**, AES-128 included. On **AES-256** PDFs (V5 / R5 / R6) the script exits with a message: there is no owner-crack path with this tool.
- The password is found **only if it's in the wordlist**. Randomly generated owner passwords (32+ characters) are effectively unrecoverable by dictionary.
- Speed: ~3400 pw/s per core (bounded by the 50×MD5 + 20×RC4 chain per candidate, which can't be parallelized *within* a single password). Scales linearly with the number of cores.

---

## How it works

An encrypted PDF does not "contain" the password: it contains the `/O` and `/U` (owner and user) entries of the encryption dictionary. Verifying a candidate means re-running the derivation algorithm and comparing the result against `/O`.

1. **Extraction** (pyhanko): reads `/V`, `/R`, `/Length`, `/O` from the `/Encrypt` dictionary.
2. **Candidate check** (PDF 1.7, algorithm 3.3):
   - derive the owner key: `MD5(pad(password))`, then 50× MD5 (R≥3), first `keylen/8` bytes;
   - RC4-encrypt the cleartext user password (padding if empty), 20 rounds with an XOR-iterated key (R≥3);
   - compare the first 16 bytes (R3/R4) or 32 bytes (R2) against `/O`.
3. **Parallelism**: the wordlist is split into chunks distributed across cores.

The verification algorithm is ported 1:1 from the `$pdfo$` format of John the Ripper (by Didier Stevens) and is validated at startup with `--selftest` against the official public test vectors.

---

## Legal note

This is a **password-recovery** tool for your own documents or ones you are authorized to test. Using it on files without permission may be illegal.

---

## License

GNU General Public License v3.0 — see `LICENSE`.

## Credits

- **Owner-verification algorithm** ported from the `$pdfo$` format for
  John the Ripper by Didier Stevens
  (<https://github.com/DidierStevens/john>).
- The John the Ripper PDF cracking code it builds on is
  © 2012 Dhiru Kholia, © 2013 Shane Quigley, and uses code from
  pdfcrack, Sumatra PDF and MuPDF (GPL).
- PDF encryption metadata parsing via
  [pyHanko](https://github.com/MatthiasValvekens/pyHanko) (MIT).
- `rockyou.txt` is **not** bundled: it is downloaded at runtime from the
  [naive-hashcat](https://github.com/brannondorsey/naive-hashcat) release.
  It is a widely used public password list.
