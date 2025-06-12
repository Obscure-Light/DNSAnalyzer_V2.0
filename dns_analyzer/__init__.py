"""dns_analyzer package – espone la logica (core) e la GUI.

Installazione in sviluppo::

    pip install -e .

Esecuzione::

    python -m dns_analyzer            # avvia la GUI
    python -m dns_analyzer --help     # info CLI (pass-through a main.py)

Il package è composto da due moduli principali:
    * **core** – classe `DNSAnalyzer` con tutta la logica di query DNS e
      best‑practice.
    * **gui**  – classe `DNSAnalyzerGUI` basata su Tkinter che sfrutta il core.

Questo file re‑esporta le due classi per un'importazione semplificata::

    from dns_analyzer import DNSAnalyzer, DNSAnalyzerGUI
"""

from __future__ import annotations

from importlib import metadata as _meta

from .core import DNSAnalyzer  # noqa: E402 (import posposto)
from .gui import DNSAnalyzerGUI  # noqa: E402

__all__ = ["DNSAnalyzer", "DNSAnalyzerGUI", "__version__"]

# ----------------------------------------------------------------------------
# Versione
# ----------------------------------------------------------------------------
try:
    __version__: str = _meta.version("dns_analyzer")
except _meta.PackageNotFoundError:  # pragma: no cover – ambiente dev non installato
    __version__ = "0.0.0-dev"

# ----------------------------------------------------------------------------
# Esecuzione come modulo (`python -m dns_analyzer`)
# ----------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover – runtime path
    import sys as _sys
    import tkinter as _tk

    # Pass‑through alla CLI se viene richiesto un argomento (es. --cli)
    if len(_sys.argv) > 1 and _sys.argv[1].startswith("-"):
        from pathlib import Path as _Path
        from typing import List as _List  # noqa: WPS433 – shadow built‑ins

        import argparse as _argparse

        from .core import DNSAnalyzer as _DNSAnalyzer
        from .main import _run_cli as _run_cli  # type: ignore[attr-defined]

        parser = _argparse.ArgumentParser(prog="python -m dns_analyzer", description="DNS Analyzer CLI")
        parser.add_argument("-d", "--domain", action="append", required=True, help="Dominio (ripetibile)")
        parser.add_argument("-s", "--selector", action="append", help="Selettore DKIM (ripetibile)")
        parser.add_argument("-b", "--best", action="store_true", help="Abilita best‑practice")
        parser.add_argument("-o", "--output", type=_Path, help="File CSV/XLSX/JSON per i risultati")
        args = parser.parse_args(_sys.argv[1:])
        _run_cli(args.domain, args.selector or [], args.best, args.output)
        _sys.exit(0)

    # Default: avvia GUI
    root = _tk.Tk()
    DNSAnalyzerGUI(root)
    root.mainloop()