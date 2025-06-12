#!/usr/bin/env python3
"""
Main entry‑point per **DNS Analyzer**.

Esegue la GUI Tk oppure, con l'opzione `--cli`, permette l'uso da riga di
comando senza interfaccia grafica.

Esempi
-------
GUI classica::

    python main.py

CLI, con esportazione CSV::

    python main.py --cli -d example.com -d example.org -s default -b -o risultati.csv

Dipendenze: dnspython, pandas, tkinter (incluso in Python standard).
"""

from __future__ import annotations

import argparse
import sys
import tkinter as tk
from pathlib import Path
from typing import List

import pandas as pd

try:
    from dns_analyzer import DNSAnalyzer, DNSAnalyzerGUI
except ImportError as exc:  # pragma: no cover – guidance for user
    sys.exit(f"Impossibile importare il pacchetto dns_analyzer: {exc}\n\n"
             "Assicurati di avere la struttura del progetto corretta e di essere nello stesso "
             "directory (o installa il pacchetto con `pip install -e .`).")


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------

def _run_cli(domains: List[str], selectors: List[str], best: bool, out: Path | None) -> None:
    """Esegue l'analisi in modalità CLI e stampa/esporta i risultati."""
    analyzer = DNSAnalyzer(domains, dkim_selectors=selectors, enable_best_practices=best)
    df = analyzer.run()
    pd.set_option("display.max_colwidth", None)
    print(df.to_markdown(index=False))

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.suffix.lower() == ".csv":
            df.to_csv(out, index=False)
        elif out.suffix.lower() in {".xlsx", ".xls"}:
            df.to_excel(out, index=False)
        else:
            df.to_json(out, orient="records", indent=2)
        print(f"\nRisultati salvati in: {out}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: List[str] | None = None) -> None:  # noqa: D401 – CLI entry
    parser = argparse.ArgumentParser(description="DNS Analyzer – GUI o CLI")
    parser.add_argument(
        "--cli", action="store_true", help="Usa la modalità a riga di comando (senza GUI)"
    )
    parser.add_argument(
        "-d", "--domain", action="append", metavar="DOM", help="Dominio da analizzare (ripetibile)"
    )
    parser.add_argument(
        "-s", "--selector", action="append", metavar="SEL", help="Selettore DKIM (ripetibile)"
    )
    parser.add_argument(
        "-b", "--best", action="store_true", help="Abilita controlli Best Practice in CLI"
    )
    parser.add_argument(
        "-o", "--output", type=Path, metavar="PATH", help="File di output .csv/.xlsx/.json"
    )
    args = parser.parse_args(argv)

    # --- CLI path ---------------------------------------------------------
    if args.cli:
        if not args.domain:
            parser.error("Con --cli è obbligatorio almeno un --domain")
        _run_cli(args.domain, args.selector or [], args.best, args.output)
        return

    # --- GUI path ---------------------------------------------------------
    root = tk.Tk()
    DNSAnalyzerGUI(root)
    root.mainloop()


# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover – invoked directly
    main()