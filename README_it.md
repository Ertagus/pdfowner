# pdfowner.py

Estrae e cracka la **owner password** (password di modifica/permessi) di un PDF in un unico passaggio: legge l'hash dal file, poi lo attacca a dizionario in multi-core.

Utile per PDF che si aprono senza password ma bloccano modifica/stampa/copia.

---

## Requisiti

- **Python 3.8+**
- **pyhanko** — estrazione hash dal PDF (obbligatorio)
- **pycryptodome** — RC4 in C, ~2× più veloce (opzionale, c'è fallback puro-Python)

Le dipendenze si **installano da sole** al primo avvio se mancano. Per installarle a mano:

```
python -m pip install pyhanko pycryptodome
```

---

## Uso

```
python pdfowner.py <file.pdf> [wordlist.txt] [opzioni]
```

### Drag & drop (Windows)

Il modo piu' rapido: **trascina un PDF sull'icona di `pdfowner.py`**. Parte da solo, senza wordlist (usa/scarica rockyou.txt), e resta aperto a fine crack grazie alla pausa finale.

Prerequisito una tantum: associare i file `.py` a Python.
- Tasto destro su un `.py` -> *Apri con* -> *Scegli un'altra app* -> Python -> *Usa sempre*.
- Oppure da prompt admin:
  ```
  assoc .py=Python.File
  ftype Python.File="C:\percorso\python.exe" "%1" %*
  ```
  (il `%*` finale passa gli argomenti, incluso il PDF trascinato)

Al **primo avvio** installa da sola pyhanko + pycryptodome e scarica rockyou.txt; agli avvii successivi parte diretta.

### Opzioni

| Flag | Descrizione |
|------|-------------|
| `-u`, `--user-pw PW` | User password in chiaro, se il PDF ne ha anche una di apertura (default: vuota) |
| `-c`, `--cores N` | Numero di core da usare (default: tutti) |
| `--no-install` | Non installare le dipendenze mancanti; esce con l'istruzione pip |
| `--selftest` | Verifica l'algoritmo sui vettori di test noti, poi esce |

### Wordlist automatica

Se **non** passi la wordlist:

1. cerca `rockyou.txt` nella cartella corrente (poi in quella dello script);
2. se non c'è, la **scarica da sola** da GitHub (~140 MB) con barra di avanzamento.

Con `--no-install` il download è disattivato: se manca la wordlist, esce con istruzioni.

### Output colorato

Ogni fase è segnalata a colori: `::` fase, `->` info, `OK` verde, `!!` giallo (warning), `XX` rosso (errore). Es. dipendenza mancante → installo, wordlist assente → scarico, ecc. Su Windows i colori sono abilitati automaticamente (VT mode).

### Esempi

```
REM crack base: niente wordlist -> usa/scarica rockyou.txt, tutti i core
python pdfowner.py documento.pdf

REM wordlist esplicita
python pdfowner.py documento.pdf rockyou.txt

REM forza 4 core
python pdfowner.py documento.pdf rockyou.txt -c 4

REM PDF con anche password di apertura nota
python pdfowner.py documento.pdf rockyou.txt -u "aperturaPW"

REM ambiente controllato, niente auto-install
python pdfowner.py documento.pdf rockyou.txt --no-install

REM verifica che l'algoritmo sia corretto
python pdfowner.py --selftest
```

### Output

```
=== pdfowner.py ===  RC4=C  core=8
:: Estrazione hash owner
  OK R4  keylen=128  (AES-128)
     $pdfo$4*4*128*32*<owner-hash>*0*
:: Wordlist
  OK trovata rockyou.txt
:: Crack
  -> 400000/14344391  14328 pw/s

[+] OWNER PASSWORD: <password>  (39s)
```

La riga `$pdfo$...` è l'hash estratto: riutilizzabile con la build patchata di John the Ripper (format `$pdfo$` di Didier Stevens), se preferisci.

---

## Wordlist

`rockyou.txt` (~140 MB, 14M password) è lo standard di partenza:
- release `naive-hashcat` su GitHub
- oppure pacchetto SecLists

Metti il file nella stessa cartella o passa il percorso completo.

---

## Limiti

- **Solo RC4 (revisioni R2 / R3 / R4)**, AES-128 incluso. Su PDF **AES-256** (V5 / R5 / R6) lo script esce con un messaggio: non esiste una via di crack owner con questo strumento.
- La password si trova **solo se è nel wordlist**. Owner password generate a caso (32+ caratteri) sono di fatto irrecuperabili a dizionario.
- Velocità: ~3400 pw/s per core (tetto imposto dalla catena 50×MD5 + 20×RC4 per candidato, non parallelizzabile *dentro* la singola password). Scala lineare col numero di core.

---

## Come funziona

Un PDF cifrato non "contiene" la password: contiene le voci `/O` e `/U` (owner e user) del dizionario di cifratura. Verificare una candidata significa rieseguire l'algoritmo di derivazione e confrontare il risultato con `/O`.

1. **Estrazione** (pyhanko): legge `/V`, `/R`, `/Length`, `/O` dal dizionario `/Encrypt`.
2. **Verifica candidata** (algoritmo 3.3, PDF 1.7):
   - deriva la chiave owner: `MD5(pad(password))`, poi 50× MD5 (R≥3), primi `keylen/8` byte;
   - cifra RC4 la user password in chiaro (padding se vuota), 20 round con chiave XOR-iterata (R≥3);
   - confronta i primi 16 byte (R3/R4) o 32 (R2) con `/O`.
3. **Parallelismo**: il wordlist è diviso in blocchi distribuiti sui core.

L'algoritmo di verifica è portato 1:1 dal format `$pdfo$` di John the Ripper (Didier Stevens) ed è validato all'avvio con `--selftest` sui vettori di test ufficiali.

---

## Nota legale

Strumento di **recupero password** per documenti propri o su cui si è autorizzati. Usarlo su file altrui senza permesso può violare la legge.

---

## Licenza

GNU General Public License v3.0 — vedi `LICENSE`.

## Crediti

- **Algoritmo di verifica owner** portato dal format `$pdfo$` per
  John the Ripper di Didier Stevens
  (<https://github.com/DidierStevens/john>).
- Il codice di cracking PDF di John the Ripper su cui si basa è
  © 2012 Dhiru Kholia, © 2013 Shane Quigley, e usa codice di
  pdfcrack, Sumatra PDF e MuPDF (GPL).
- Parsing dei metadati di cifratura PDF via
  [pyHanko](https://github.com/MatthiasValvekens/pyHanko) (MIT).
- `rockyou.txt` **non** è inclusa: viene scaricata a runtime dalla release
  [naive-hashcat](https://github.com/brannondorsey/naive-hashcat).
  È una lista di password pubblica di uso comune nel settore.
