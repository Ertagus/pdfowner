#!/usr/bin/env python3
#
# pdfowner - estrae e cracka le owner password dei PDF
# Copyright (C) 2026 <nome>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Owner-verification algorithm derived from the $pdfo$ format for
# John the Ripper by Didier Stevens.
"""
pdfowner.py - estrae e cracka la OWNER password di un PDF in un colpo solo.
Supporta RC4 R2/3/4 (AES-128 incluso). AES-256 (V5/R5/R6) NON supportato.

Uso:
  python pdfowner.py file.pdf [wordlist.txt] [-u USERPW] [-c NCORE]
  python pdfowner.py --selftest

Se la wordlist non e' specificata: usa rockyou.txt nella cartella corrente,
e se manca la scarica automaticamente.

Dipendenze (auto-install se assenti): pyhanko (obbligatorio), pycryptodome (opzionale).

Una owner password limita modifica/stampa/copia; il documento puo' aprirsi senza
alcuna password. Strumento di recupero password per file propri o su cui si e'
autorizzati. Verifica la voce owner secondo l'algoritmo 3.3 del PDF 1.7.
"""
import sys, os, hashlib, time, argparse, importlib, subprocess

# ---------------------------------------------------------------- COLORI
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
    print(f"\n{C.DIM}Premere un tasto per terminare...{C.R}", end="", flush=True)
    try:
        try:
            import msvcrt                     # Windows: singolo tasto
            msvcrt.getch()
        except ImportError:
            import termios, tty               # Unix: singolo tasto raw
            fd=sys.stdin.fileno(); old=termios.tcgetattr(fd)
            try: tty.setraw(fd); sys.stdin.read(1)
            finally: termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        try: input()                          # fallback: INVIO
        except (EOFError, KeyboardInterrupt): pass
    print()

# ---------------------------------------------------- DIPENDENZE auto-install
def ensure_dep(pip_name, import_name=None, required=True, auto=True):
    mod = import_name or pip_name
    try:
        return importlib.import_module(mod)
    except ImportError:
        if not auto:
            if required: die(f"Manca {pip_name}:  python -m pip install {pip_name}")
            return None
        warn(f"{pip_name} assente")
        info(f"installo {pip_name}...")
        base=[sys.executable,"-m","pip","install"]
        try:
            try:
                subprocess.check_call(base+[pip_name])
            except subprocess.CalledProcessError:
                subprocess.check_call(base+["--break-system-packages",pip_name])  # PEP 668
            importlib.invalidate_caches()
            m=importlib.import_module(mod)
            ok(f"{pip_name} installato")
            return m
        except Exception as e:
            if required: die(f"Installazione {pip_name} fallita: {e}")
            warn(f"{pip_name} non installato ({e}); proseguo senza")
            return None

_AUTO = "--no-install" not in sys.argv

# ---------------------------------------------------------------- RC4 + costanti
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

# ------------------------------------------- WORDLIST auto + download rockyou
ROCKYOU_URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

def download_rockyou(dest):
    import urllib.request
    info("scarico rockyou.txt da GitHub (~140 MB)...")
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
        ok(f"rockyou.txt scaricata ({os.path.getsize(dest)//1048576} MB, {time.time()-t:.0f}s)")
    except Exception as e:
        if os.path.exists(dest):
            try: os.remove(dest)
            except: pass
        die(f"download fallito: {e}\n     scaricala a mano: {ROCKYOU_URL}")

def resolve_wordlist(arg, auto=True):
    step("Wordlist")
    if arg:
        if not os.path.isfile(arg): die(f"wordlist non trovata: {arg}")
        ok(f"uso {arg}")
        return arg
    info("nessuna wordlist specificata -> cerco rockyou.txt")
    here=os.path.dirname(os.path.abspath(__file__))
    for cand in ("rockyou.txt", os.path.join(here,"rockyou.txt")):
        if os.path.isfile(cand):
            ok(f"trovata {cand}")
            return cand
    warn("rockyou.txt non presente")
    if not auto: die("rockyou.txt mancante e --no-install attivo. Passa una wordlist o scaricala.")
    dest=os.path.join(os.getcwd(),"rockyou.txt")
    download_rockyou(dest)
    return dest

# ---------------------------------------------------- ESTRAZIONE hash owner
def extract_pdfo(pdf_path, user_pw=""):
    step("Estrazione hash owner")
    if not os.path.isfile(pdf_path): die(f"PDF non trovato: {pdf_path}")
    ensure_dep("pyhanko", "pyhanko.pdf_utils.reader", required=True, auto=_AUTO)
    from pyhanko.pdf_utils.reader import PdfFileReader
    with open(pdf_path,"rb") as f:
        pdf=PdfFileReader(f, strict=False)
        enc=pdf.encrypt_dict
        if not enc: die("PDF non cifrato.")
        V=int(enc.get("/V")); R=int(enc["/R"]); length=int(enc.get("/Length",40))
        if R not in (2,3,4):
            die(f"R={R}: owner AES-256 (V5/R5/R6) non supportato. Solo RC4 R2/3/4.")
        odata=bytes(pdf.security_handler.odata[:32])
    ok(f"R{R}  keylen={length}  ({'AES-128' if V==4 else 'RC4'})")
    return dict(V=V, R=R, length=length, N=length//8, O=odata, u=bytes(user_pw.encode()[:32]))

# ------------------------------------------- VERIFICA candidato (algoritmo 3.3)
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
    # vettori di test pubblici (formato $pdfo$ di John the Ripper)
    vecs=[("$pdfo$1*2*40*32*7303809eaf677bdb5ca64b9d8cb0ccdd47d09a7b28ad5aa522c62685c6d9e499*4*test","test"),
          ("$pdfo$2*3*128*32*09523923ee2f8e95c3e4688a1b508d6c7540d52a4afafd4cb2a8fa796b335116*4*test","secret")]
    ok_all=True
    for h,pw in vecs:
        f=h[6:].split("*")
        _init(dict(R=int(f[1]),N=int(f[2])//8,O=bytes.fromhex(f[4]),
                   u=(f[6].encode() if len(f)>6 else b"")[:int(f[5])]))
        r=_check(pw.encode())
        (ok if r else err)(f"vettore pw={pw!r}"); ok_all&=r
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
        add_help=False,   # niente -h
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Estrae e cracka la OWNER password (modifica/permessi) di un PDF.\n"
                    "Supporta cifratura RC4 revisioni R2/R3/R4 (AES-128 incluso).\n"
                    "AES-256 (V5/R5/R6) NON supportato.",
        epilog="Esempi:\n"
               "  pdfowner.py file.pdf                    crack con rockyou.txt (auto-scaricata)\n"
               "  pdfowner.py file.pdf lista.txt          usa una wordlist specifica\n"
               "  pdfowner.py file.pdf -c 4               limita a 4 core\n"
               "  pdfowner.py file.pdf -u apertura        PDF con anche password di apertura\n"
               "  pdfowner.py --selftest                  verifica l'algoritmo ed esce\n\n"
               "Trascina un PDF sull'icona dello script per avviarlo senza digitare comandi.")
    ap.add_argument("pdf", metavar="FILE.PDF",
                    help="PDF da attaccare (owner-protected).")
    ap.add_argument("wordlist", nargs="?", default=None, metavar="WORDLIST",
                    help="Lista di password da provare. Se omessa usa rockyou.txt nella "
                         "cartella corrente; se non c'e', la scarica da GitHub (~140 MB).")
    ap.add_argument("-u","--user-pw", default="", metavar="PW",
                    help="Password di APERTURA in chiaro, se il PDF ne ha una oltre a quella "
                         "owner. Default: vuota (caso tipico: PDF che si apre senza chiedere nulla).")
    ap.add_argument("-c","--cores", type=int, default=cpu_count(), metavar="N",
                    help=f"Numero di core CPU da usare in parallelo. Default: tutti "
                         f"({cpu_count()} su questa macchina). Piu' core = piu' veloce.")
    ap.add_argument("--selftest", action="store_true",
                    help="Verifica che l'algoritmo di crack sia corretto (vettori di test noti), "
                         "poi esce. Non serve un PDF.")
    ap.add_argument("--no-install", action="store_true",
                    help="Non installare le dipendenze mancanti ne' scaricare rockyou.txt: "
                         "in caso di assenza esce con le istruzioni. Utile in ambienti controllati.")
    if len(sys.argv)==1:               # avviato senza argomenti -> help completo
        ap.print_help(); pause(); sys.exit(0)
    a=ap.parse_args()

    print(f"{C.B}{C.MAG}=== pdfowner.py ==={C.R}  RC4={'C' if RC4_C else 'py'}  core={a.cores}")

    s=extract_pdfo(a.pdf, a.user_pw)
    print(f"{C.DIM}     $pdfo${s['V']}*{s['R']}*{s['length']}*{len(s['O'])}*{s['O'].hex()}*{len(s['u'])}*{a.user_pw}{C.R}")

    wl=resolve_wordlist(a.wordlist, auto=_AUTO)

    step("Crack")
    pws=[l.rstrip(b"\r\n") for l in open(wl,"rb")]
    info(f"{len(pws)} candidate")
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
        print(f"{C.B}{C.RED}[-] non trovata{C.R}  ({dt:.0f}s)")
    pause()

# ---------------------------------------------------------------- deps RC4 + entry
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
