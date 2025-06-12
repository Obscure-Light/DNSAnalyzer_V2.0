# DNS Analyzer

> **Analizza record DNS & best‑practice con GUI Tkinter o CLI.**
> Supporta SPF · DMARC · DKIM · BIMI · MX · A/AAAA · NS · altri record.

---

## Sommario

1. [Caratteristiche](#caratteristiche)
2. [Installazione](#installazione)
3. [Esecuzione GUI](#esecuzione-gui)
4. [Esecuzione CLI](#esecuzione-cli)
5. [Esportazione](#esportazione)
6. [Struttura del progetto](#struttura-del-progetto)
7. [Contribuire](#contribuire)

---

## Caratteristiche

| Funzione              | Dettagli                                                                                                            |
| --------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Multi‑dominio**     | Importa da **.txt/.csv** o aggiungi manualmente.                                                                    |
| **Record supportati** | A, AAAA, MX, NS, CNAME, TXT, SPF, DMARC, DKIM, BIMI, SOA, CAA.                                                      |
| **Best‑practice**     | Flag opzionale che assegna *Severity* (INFO/WARN/CRITICAL) e note su record SPF, DMARC, DKIM, BIMI, MX, A/AAAA, NS. |
| **GUI Tkinter**       | Interfaccia scrollabile, tema *clam*.                                                                               |
| **CLI**               | Stesse funzionalità senza interfaccia grafica.                                                                      |
| **Esportazione**      | CSV · Excel (.xlsx) · JSON.                                                                                         |
| **Modulare**          | Logica in `dns_analyzer/core.py`, GUI in `dns_analyzer/gui.py`.                                                     |

---

## Installazione

```bash
# clona il repo
git clone https://github.com/tuo-utente/dns-analyzer.git
cd dns-analyzer

# crea e attiva un venv facoltativo\python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# dipendenze
pip install -r requirements.txt  # oppure:
pip install dnspython pandas
```

> **Tkinter** è incluso di default in Python su Windows/macOS. Su alcune distro Linux potrebbe servire il pacchetto `python3‑tk`.

---

## Esecuzione GUI

```bash
python main.py                # oppure
python -m dns_analyzer         # richiede l'installazione editable
```

### Passaggi rapidi

1. Aggiungi uno o più domini.
2. (Facoltativo) Aggiungi selettori DKIM.
3. Spunta i record da verificare – «Seleziona Tutto» per flag rapida.
4. (Facoltativo) Abilita «Analisi Best Practice».
5. **Avvia Analisi** → risultati nell'area testo.
6. **Esporta Risultati** in CSV/XLSX/JSON.

---

## Esecuzione CLI

```bash
python main.py --cli \
  -d example.com -d example.org \
  -s default -s selector2 \
  -b                     # abilita best‑practice

# salva in CSV
python main.py --cli -d example.com -o report.csv
```

Parametri principali:

| Opzione             | Descrizione                            |
| ------------------- | -------------------------------------- |
| `--cli`             | Usa modalità riga di comando.          |
| `-d, --domain`      | Dominio da analizzare (ripetibile).    |
| `-s, --selector`    | Selettore DKIM (ripetibile).           |
| `-b, --best`        | Abilita analisi best‑practice.         |
| `-o, --output PATH` | File di output (.csv / .xlsx / .json). |

---

## Esportazione

| Formato   | Metodo                                        | Note                                                                          |
| --------- | --------------------------------------------- | ----------------------------------------------------------------------------- |
| **CSV**   | GUI ▷ «Esporta → CSV»<br>CLI `-o report.csv`  | UTF‑8, separatore virgola.                                                    |
| **Excel** | GUI ▷ «Excel (.xlsx)»<br>CLI `-o report.xlsx` | Richiede **openpyxl** (installato automaticamente se usi `requirements.txt`). |
| **JSON**  | GUI ▷ «JSON»<br>CLI `-o report.json`          | Array di oggetti.                                                             |

---

## Struttura del progetto

```
dns-analyzer/
├─ dns_analyzer/
│  ├─ __init__.py      # re‑export core & GUI
│  ├─ core.py          # classe DNSAnalyzer (business‑logic)
│  └─ gui.py           # interfaccia Tkinter
├─ main.py             # entry‑point GUI/CLI
├─ requirements.txt
└─ README.md
```


