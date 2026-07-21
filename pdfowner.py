#!/usr/bin/env python3
"""
pdfowner.py - extract and crack the OWNER password of a PDF in one shot.
Supports RC4 R2/3/4 (AES-128 included). AES-256 (V5/R5/R6) NOT supported.

Usage:
  python pdfowner.py file.pdf [wordlist.txt] [-u USERPW] [-c NCORE]
  python pdfowner.py --selftest

If the wordlist is not given, rockyou.txt in the current folder is used,
and downloaded automatically if missing.

Dependencies (auto-installed if absent): pyhanko (required), pycryptodome (optional).

An owner password restricts editing/printing/copying; the document itself may open
without any password. This tool is for password recovery on files you own or are
authorized to test. Verifies the owner entry per PDF 1.7 algorithm 3.3.
"""
import sys, os, hashlib, time, argparse, importlib, subprocess

# ---------------------------------------------------------------- COLORS
def _enable_ansi():
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            os.system("")
_enable_ansi()

class C:
    R="\033[0m"; B="\033[1m"; DIM="\033[2m"
    RED="\033[91m"; GRN="\033[92m"; YEL="\033[93m"; BLU="\033[94m"; CYA="\033[96m"; MAG="\033[95m"

def step(msg): print(f"{C.B}{C.BLU}::{C.R} {C.B}{msg}{C.R}", flush=True)
def info(msg): print(f"{C.CYA}  ->{C.R} {msg}", flush=True)
def ok(msg):   print(f"{C.GRN}  OK{C.R} {msg}", flush=True)
def warn(msg): print(f"{C.YEL}  !!{C.R} {msg}", flush=True)
def err(msg):  print(f"{C.RED}  XX{C.R} {msg}", flush=True)
def die(msg):  err(msg); pause(); sys.exit(1)

def pause():
    print(f"\n{C.DIM}Press any key to exit...{C.R}", end="", flush=True)
    try:
        try:
            import msvcrt                     # Windows: single keypress
            msvcrt.getch()
        except ImportError:
            import termios, tty               # Unix: single raw keypress
            fd=sys.stdin.fileno(); old=termios.tcgetattr(fd)
            try: tty.setraw(fd); sys.stdin.read(1)
            finally: termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        try: input()                          # fallback: ENTER
        except (EOFError, KeyboardInterrupt): pass
    print()

# ---------------------------------------------------- DEPENDENCIES auto-install
def ensure_dep(pip_name, import_name=None, required=True, auto=True):
    mod = import_name or pip_name
    try:
        return importlib.import_module(mod)
    except ImportError:
        if not auto:
            if required: die(f"Missing {pip_name}:  python -m pip install {pip_name}")
            return None
        warn(f"{pip_name} not found")
        info(f"installing {pip_name}...")
        base=[sys.executable,"-m","pip","install"]
        try:
            try:
                subprocess.check_call(base+[pip_name])
            except subprocess.CalledProcessError:
                subprocess.check_call(base+["--break-system-packages",pip_name])  # PEP 668
            importlib.invalidate_caches()
            m=importlib.import_module(mod)
            ok(f"{pip_name} installed")
            return m
        except Exception as e:
            if required: die(f"Installing {pip_name} failed: {e}")
            warn(f"{pip_name} not installed ({e}); continuing without it")
            return None

_AUTO = "--no-install" not in sys.argv

# ---------------------------------------------------------------- RC4 + constants
def _rc4_py(key, data):
    S=list(range(256)); j=0; kl=len(key)
    for i in range(256):
        j=(j+S[i]+key[i%kl])&0xff; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for b in data:
        i=(i+1)&0xff; j=(j+S[i])&0xff; S[i],S[j]=S[j],S[i]
        out.append(b^S[(S[i]+S[j])&0xff])
    return bytes(out)

md5 = hashlib.md5
PADDING = bytes([
0x28,0xbf,0x4e,0x5e,0x4e,0x75,0x8a,0x41,0x64,0x00,0x4e,0x56,0xff,0xfa,0x01,0x08,
0x2e,0x2e,0x00,0xb6,0xd0,0x68,0x3e,0x80,0x2f,0x0c,0xa9,0xfe,0x64,0x53,0x69,0x7a])

# ------------------------------------------- WORDLIST auto + rockyou download
ROCKYOU_URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

def download_rockyou(dest):
    import urllib.request
    info("downloading rockyou.txt from GitHub (~140 MB)...")
    t=time.time(); last=[-1]
    def hook(blocks, bs, total):
        done=blocks*bs
        if total>0:
            pct=min(100,done*100//total)
            if pct!=last[0]:
                last[0]=pct
                bar="#"*(pct//4)+"."*(25-pct//4)
                sys.stdout.write(f"\r{C.CYA}  ->{C.R} [{bar}] {pct}%  {done//1048576}MB"); sys.stdout.flush()
    try:
        urllib.request.urlretrieve(ROCKYOU_URL, dest, hook)
        sys.stdout.write("\n")
        ok(f"rockyou.txt downloaded ({os.path.getsize(dest)//1048576} MB, {time.time()-t:.0f}s)")
    except Exception as e:
        if os.path.exists(dest):
            try: os.remove(dest)
            except: pass
        die(f"download failed: {e}\n     download it manually: {ROCKYOU_URL}")

def resolve_wordlist(arg, auto=True):
    step("Wordlist")
    if arg:
        if not os.path.isfile(arg): die(f"wordlist not found: {arg}")
        ok(f"using {arg}")
        return arg
    info("no wordlist given -> looking for rockyou.txt")
    here=os.path.dirname(os.path.abspath(__file__))
    for cand in ("rockyou.txt", os.path.join(here,"rockyou.txt")):
        if os.path.isfile(cand):
            ok(f"found {cand}")
            return cand
    warn("rockyou.txt not present")
    if not auto: die("rockyou.txt missing and --no-install is set. Pass a wordlist or download it.")
    dest=os.path.join(os.getcwd(),"rockyou.txt")
    download_rockyou(dest)
    return dest

# ---------------------------------------------------- EXTRACT owner hash
def extract_pdfo(pdf_path, user_pw=""):
    step("Extracting owner hash")
    if not os.path.isfile(pdf_path): die(f"PDF not found: {pdf_path}")
    ensure_dep("pyhanko", "pyhanko.pdf_utils.reader", required=True, auto=_AUTO)
    from pyhanko.pdf_utils.reader import PdfFileReader
    with open(pdf_path,"rb") as f:
        pdf=PdfFileReader(f, strict=False)
        enc=pdf.encrypt_dict
        if not enc: die("PDF is not encrypted.")
        V=int(enc.get("/V")); R=int(enc["/R"]); length=int(enc.get("/Length",40))
        if R not in (2,3,4):
            die(f"R={R}: owner AES-256 (V5/R5/R6) not supported. RC4 R2/3/4 only.")
        odata=bytes(pdf.security_handler.odata[:32])
    ok(f"R{R}  keylen={length}  ({'AES-128' if V==4 else 'RC4'})")
    return dict(V=V, R=R, length=length, N=length//8, O=odata, u=bytes(user_pw.encode()[:32]))

# ------------------------------------------- CANDIDATE check (algorithm 3.3)
_S=None
def _init(s):
    global _S; _S=s
    s["ubuf"]=(s["u"]+PADDING)[:32]
    s["ncmp"]=16 if s["R"] in (3,4) else 32
    s["Ocmp"]=s["O"][:s["ncmp"]]
    s["masks"]=[int.from_bytes(bytes([i])*s["N"],'big') for i in range(20)]

def _check(pw):
    s=_S; R,N=s["R"],s["N"]
    k=md5((pw[:32]+PADDING)[:32]).digest()
    if R>=3:
        for _ in range(50): k=md5(k[:N]).digest()
    k=k[:N]; out=rc4(k,s["ubuf"])
    if R>=3:
        ki=int.from_bytes(k,'big'); ms=s["masks"]
        for i in range(1,20):
            out=rc4((ki^ms[i]).to_bytes(N,'big'),out)
    return out[:s["ncmp"]]==s["Ocmp"]

def _worker(chunk):
    for pw in chunk:
        if _check(pw): return pw
    return None

# ---------------------------------------------------------------- SELFTEST
def selftest():
    # public test vectors (John the Ripper $pdfo$ format)
    vecs=[("$pdfo$1*2*40*32*7303809eaf677bdb5ca64b9d8cb0ccdd47d09a7b28ad5aa522c62685c6d9e499*4*test","test"),
          ("$pdfo$2*3*128*32*09523923ee2f8e95c3e4688a1b508d6c7540d52a4afafd4cb2a8fa796b335116*4*test","secret")]
    ok_all=True
    for h,pw in vecs:
        f=h[6:].split("*")
        _init(dict(R=int(f[1]),N=int(f[2])//8,O=bytes.fromhex(f[4]),
                   u=(f[6].encode() if len(f)>6 else b"")[:int(f[5])]))
        r=_check(pw.encode())
        (ok if r else err)(f"vector pw={pw!r}"); ok_all&=r
    return ok_all

# ---------------------------------------------------------------- MAIN
def main():
    from multiprocessing import Pool, cpu_count
    class PausingParser(argparse.ArgumentParser):
        def error(self, message):
            self.print_help()
            print()
            err(message)
            pause()
            self.exit(2)
    ap=PausingParser(
        prog="pdfowner.py",
        add_help=False,   # no -h
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Extract and crack the OWNER password (edit/permissions) of a PDF.\n"
                    "Supports RC4 encryption revisions R2/R3/R4 (AES-128 included).\n"
                    "AES-256 (V5/R5/R6) NOT supported.",
        epilog="Examples:\n"
               "  pdfowner.py file.pdf                    crack with rockyou.txt (auto-downloaded)\n"
               "  pdfowner.py file.pdf list.txt           use a specific wordlist\n"
               "  pdfowner.py file.pdf -c 4               limit to 4 cores\n"
               "  pdfowner.py file.pdf -u openpw          PDF that also has an open password\n"
               "  pdfowner.py --selftest                  verify the algorithm and exit\n\n"
               "Drag a PDF onto the script icon to run it without typing any command.")
    ap.add_argument("pdf", metavar="FILE.PDF",
                    help="PDF to attack (owner-protected).")
    ap.add_argument("wordlist", nargs="?", default=None, metavar="WORDLIST",
                    help="Password list to try. If omitted, rockyou.txt in the current "
                         "folder is used; if absent, it is downloaded from GitHub (~140 MB).")
    ap.add_argument("-u","--user-pw", default="", metavar="PW",
                    help="Cleartext OPEN password, if the PDF has one in addition to the owner "
                         "password. Default: empty (typical case: PDF opens without prompting).")
    ap.add_argument("-c","--cores", type=int, default=cpu_count(), metavar="N",
                    help=f"Number of CPU cores to run in parallel. Default: all "
                         f"({cpu_count()} on this machine). More cores = faster.")
    ap.add_argument("--selftest", action="store_true",
                    help="Verify the crack algorithm against known test vectors, then exit. "
                         "No PDF needed.")
    ap.add_argument("--no-install", action="store_true",
                    help="Do not install missing dependencies nor download rockyou.txt: "
                         "if something is missing, exit with instructions. Useful in locked-down envs.")
    if len(sys.argv)==1:               # launched with no arguments -> full help
        ap.print_help(); pause(); sys.exit(0)
    a=ap.parse_args()

    print(f"{C.B}{C.MAG}=== pdfowner.py ==={C.R}  RC4={'C' if RC4_C else 'py'}  cores={a.cores}")

    s=extract_pdfo(a.pdf, a.user_pw)
    print(f"{C.DIM}     $pdfo${s['V']}*{s['R']}*{s['length']}*{len(s['O'])}*{s['O'].hex()}*{len(s['u'])}*{a.user_pw}{C.R}")

    wl=resolve_wordlist(a.wordlist, auto=_AUTO)

    step("Crack")
    pws=[l.rstrip(b"\r\n") for l in open(wl,"rb")]
    info(f"{len(pws)} candidates")
    CH=10000; chunks=[pws[i:i+CH] for i in range(0,len(pws),CH)]
    t=time.time(); found=None
    with Pool(a.cores, initializer=_init, initargs=(s,)) as p:
        for i,res in enumerate(p.imap(_worker, chunks)):
            if res is not None: found=res; p.terminate(); break
            if (i+1)%20==0:
                done=(i+1)*CH
                info(f"{done}/{len(pws)}  {done/(time.time()-t):.0f} pw/s")
    dt=time.time()-t
    print()
    if found is not None:
        print(f"{C.B}{C.GRN}[+] OWNER PASSWORD: {found.decode('latin-1')}{C.R}  ({dt:.0f}s)")
    else:
        print(f"{C.B}{C.RED}[-] not found{C.R}  ({dt:.0f}s)")
    pause()

# ---------------------------------------------------------------- RC4 deps + entry
_crypto = ensure_dep("pycryptodome", "Crypto.Cipher", required=False, auto=_AUTO)
if _crypto is not None:
    from Crypto.Cipher import ARC4
    def rc4(k,d): return ARC4.new(k).encrypt(d)
    RC4_C=True
else:
    rc4=_rc4_py; RC4_C=False

if __name__=="__main__":
    if "--selftest" in sys.argv:
        step("Selftest"); r=selftest(); pause(); sys.exit(0 if r else 1)
    main()
