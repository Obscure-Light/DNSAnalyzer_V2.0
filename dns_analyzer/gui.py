"""dns_analyzer.gui – interfaccia Tkinter per DNS Analyzer.

Dipendenze:
    * tkinter (builtin)
    * pandas
    * dns_analyzer.core (DNSAnalyzer)
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List

import pandas as pd

from .core import DNSAnalyzer

__all__ = ["DNSAnalyzerGUI"]

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _center_window(win: tk.Tk | tk.Toplevel, width: int, height: int) -> None:  # noqa: D401
    """Centra la finestra sullo schermo primario."""
    screen_w = win.winfo_screenwidth()
    screen_h = win.winfo_screenheight()
    x = int((screen_w - width) / 2)
    y = int((screen_h - height) / 2)
    win.geometry(f"{width}x{height}+{x}+{y}")


# ---------------------------------------------------------------------------
# GUI class
# ---------------------------------------------------------------------------

class DNSAnalyzerGUI:
    """Interfaccia grafica Tkinter che sfrutta :class:`DNSAnalyzer`."""

    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        self.master.title("DNS Analyzer")
        _center_window(master, 900, 640)
        self.master.minsize(700, 480)

        # Tema ttk (se disponibile)
        try:
            ttk.Style().theme_use("clam")
        except tk.TclError:
            pass

        # Stato runtime
        self.domains: List[str] = []
        self.dkim_selectors: List[str] = []
        self.selected_record_types = {
            rt: tk.BooleanVar(value=False) for rt in DNSAnalyzer.DEFAULT_RECORD_TYPES
        }
        self.enable_best_practices = tk.BooleanVar(value=False)
        self.analysis_results: pd.DataFrame | None = None

        self._build_gui()

    # ------------------------------------------------------------------ GUI
    def _build_gui(self) -> None:
        """Costruisce i widget della finestra principale."""
        canvas = tk.Canvas(self.master, highlightthickness=0)
        canvas.pack(side="left", fill="both", expand=True)
        v_scroll = ttk.Scrollbar(self.master, orient="vertical", command=canvas.yview)
        v_scroll.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=v_scroll.set)

        container = ttk.Frame(canvas)
        canvas_window = canvas.create_window((0, 0), window=container, anchor="nw")

        container.bind(
            "<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.bind(
            "<Configure>", lambda _e: canvas.itemconfigure(canvas_window, width=canvas.winfo_width())
        )

        # ---------------- Domini ----------------
        f_dom = ttk.LabelFrame(container, text="Gestione Domini")
        f_dom.pack(fill="x", padx=10, pady=6)

        self.domain_entry = ttk.Entry(f_dom, width=44)
        self.domain_entry.grid(row=0, column=0, padx=4, pady=4, sticky="w")
        ttk.Button(f_dom, text="Aggiungi", command=self._add_domain).grid(row=0, column=1, padx=4, pady=4)
        ttk.Button(f_dom, text="Importa File", command=self._import_domains).grid(row=0, column=2, padx=4, pady=4)
        ttk.Button(f_dom, text="Rimuovi", command=self._remove_domain).grid(row=0, column=3, padx=4, pady=4)

        self.domain_list = ttk.Treeview(f_dom, columns=("Domain",), show="headings", height=5)
        self.domain_list.heading("Domain", text="Dominio")
        self.domain_list.column("Domain", width=340)
        self.domain_list.grid(row=1, column=0, columnspan=4, sticky="nsew", padx=4, pady=4)
        f_dom.columnconfigure(0, weight=1)
        dom_scroll = ttk.Scrollbar(f_dom, orient="vertical", command=self.domain_list.yview)
        self.domain_list.configure(yscroll=dom_scroll.set)
        dom_scroll.grid(row=1, column=4, sticky="ns")

        # ---------------- Record ----------------
        f_rec = ttk.LabelFrame(container, text="Selezione Record DNS")
        f_rec.pack(fill="x", padx=10, pady=6)
        rec_inner = ttk.Frame(f_rec)
        rec_inner.pack(fill="x")

        col = row = 0
        for rt in DNSAnalyzer.DEFAULT_RECORD_TYPES:
            ttk.Checkbutton(rec_inner, text=rt, variable=self.selected_record_types[rt]).grid(row=row, column=col, sticky="w", padx=2, pady=2)
            col += 1
            if col > 6:
                col = 0
                row += 1

        ttk.Button(f_rec, text="Seleziona Tutto", command=lambda: [v.set(True) for v in self.selected_record_types.values()]).pack(anchor="e", padx=4, pady=4)

        # ---------------- DKIM ----------------
        f_dkim = ttk.LabelFrame(container, text="Gestione Selettori DKIM")
        f_dkim.pack(fill="x", padx=10, pady=6)

        self.dkim_entry = ttk.Entry(f_dkim, width=30)
        self.dkim_entry.grid(row=0, column=0, padx=4, pady=4, sticky="w")
        ttk.Button(f_dkim, text="Aggiungi", command=self._add_dkim).grid(row=0, column=1, padx=4, pady=4)
        ttk.Button(f_dkim, text="Importa File", command=self._import_dkim).grid(row=0, column=2, padx=4, pady=4)
        ttk.Button(f_dkim, text="Rimuovi", command=self._remove_dkim).grid(row=0, column=3, padx=4, pady=4)

        self.dkim_list = ttk.Treeview(f_dkim, columns=("Selector",), show="headings", height=4)
        self.dkim_list.heading("Selector", text="Selettore DKIM")
        self.dkim_list.column("Selector", width=200)
        self.dkim_list.grid(row=1, column=0, columnspan=4, sticky="nsew", padx=4, pady=4)
        dkim_scroll = ttk.Scrollbar(f_dkim, orient="vertical", command=self.dkim_list.yview)
        self.dkim_list.configure(yscroll=dkim_scroll.set)
        dkim_scroll.grid(row=1, column=4, sticky="ns")

        # ---------------- Risultati ----------------
        f_res = ttk.LabelFrame(container, text="Risultati Analisi")
        f_res.pack(fill="both", expand=True, padx=10, pady=6)
        self.results_text = tk.Text(f_res, wrap="word", height=12)
        self.results_text.pack(fill="both", expand=True, padx=2, pady=2)
        res_scroll = ttk.Scrollbar(f_res, orient="vertical", command=self.results_text.yview)
        self.results_text.configure(yscroll=res_scroll.set)
        res_scroll.pack(side="right", fill="y")

        # ---------------- Azioni ----------------
        f_act = ttk.Frame(container)
        f_act.pack(fill="x", padx=10, pady=8)
        ttk.Button(f_act, text="Avvia Analisi", command=self._run_analysis).pack(side="left", padx=4)
        ttk.Button(f_act, text="Esporta Risultati", command=self._export_results).pack(side="left", padx=4)
        ttk.Checkbutton(f_act, text="Abilita Analisi Best Practice", variable=self.enable_best_practices).pack(side="left", padx=8)

    # ------------------------------------------------------------------ Domain ops
    def _add_domain(self) -> None:
        dom = self.domain_entry.get().strip()
        if not dom or dom in self.domains:
            messagebox.showwarning("Attenzione", "Dominio vuoto o già presente.")
            return
        self.domains.append(dom)
        self.domain_list.insert("", "end", values=(dom,))
        self.domain_entry.delete(0, tk.END)

    def _import_domains(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text/CSV", "*.txt *.csv")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                dom = line.strip()
                if dom and dom not in self.domains:
                    self.domains.append(dom)
                    self.domain_list.insert("", "end", values=(dom,))

    def _remove_domain(self) -> None:
        for sel in self.domain_list.selection():
            dom = self.domain_list.item(sel)["values"][0]
            self.domains.remove(dom)
            self.domain_list.delete(sel)

    # ------------------------------------------------------------------ DKIM ops
    def _add_dkim(self) -> None:
        sel = self.dkim_entry.get().strip()
        if not sel or sel in self.dkim_selectors:
            messagebox.showwarning("Attenzione", "Selettore vuoto o già presente.")
            return
        self.dkim_selectors.append(sel)
        self.dkim_list.insert("", "end", values=(sel,))
        self.dkim_entry.delete(0, tk.END)

    def _import_dkim(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text/CSV", "*.txt *.csv")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                selector = line.strip()
                if selector and selector not in self.dkim_selectors:
                    self.dkim_selectors.append(selector)
                    self.dkim_list.insert("", "end", values=(selector,))

    def _remove_dkim(self) -> None:
        for sel in self.dkim_list.selection():
            dsel = self.dkim_list.item(sel)["values"][0]
            self.dkim_selectors.remove(dsel)
            self.dkim_list.delete(sel)

    # ------------------------------------------------------------------ Run analysis
    def _run_analysis(self) -> None:
        self.results_text.delete("1.0", tk.END)

        if not self.domains:
            self.results_text.insert(tk.END, "Nessun dominio da analizzare.\n")
            return

        selected = [rt for rt, var in self.selected_record_types.items() if var.get()]
        if self.enable_best_practices.get() and not selected:
            selected = ["SPF", "DMARC", "DKIM", "BIMI", "MX", "A", "AAAA", "NS"]
        if not selected:
            self.results_text.insert(tk.END, "Nessun tipo di record selezionato.\n")
            return

        analyzer = DNSAnalyzer(
            self.domains,
            dkim_selectors=self.dkim_selectors,
            enable_best_practices=self.enable_best_practices.get(),
        )
        df = analyzer.run(selected)
        self.analysis_results = df

        for _, row in df.iterrows():
            selector_part = f" ({row['Selector']})" if row["Selector"] else ""
            self.results_text.insert(
                tk.END,
                f"[{row['Domain']}] {row['RecordType']}{selector_part}: {row['Value']}\n",
            )
            if row["Severity"] and row["Severity"] != "OK":
                self.results_text.insert(
                    tk.END,
                    f"    => [SEVERITY: {row['Severity']}] {row['Issues']}\n",
                )

    # ------------------------------------------------------------------ Export
    def _export_results(self) -> None:
        if self.analysis_results is None or self.analysis_results.empty:
            messagebox.showwarning("Attenzione", "Non ci sono risultati da esportare.")
            return

        win = tk.Toplevel(self.master)
        win.title("Esporta Risultati")
        _center_window(win, 260, 150)
        win.grab_set()

        ttk.Label(win, text="Scegli il formato di esportazione:").pack(pady=12)
        ttk.Button(win, text="CSV", width=18, command=lambda: self._save_results("csv", win)).pack(pady=4)
        ttk.Button(win, text="Excel (.xlsx)", width=18, command=lambda: self._save_results("xlsx", win)).pack(pady=4)
        ttk.Button(win, text="JSON", width=18, command=lambda: self._save_results("json", win)).pack(pady=4)

    def _save_results(self, fmt: str, win: tk.Toplevel) -> None:
        win.destroy()
        filetypes = {
            "csv": [("CSV", "*.csv")],
            "xlsx": [("Excel", "*.xlsx")],
            "json": [("JSON", "*.json")],
        }[fmt]

        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}", filetypes=filetypes)
        if not path:
            return

        try:
            if fmt == "csv":
                self.analysis_results.to_csv(path, index=False)
            elif fmt == "xlsx":
                self.analysis_results.to_excel(path, index=False)
            else:
                self.analysis_results.to_json(path, orient="records", indent=2)
            messagebox.showinfo("Esportazione completata", f"File salvato: {path}")
        except Exception as exc:  # pragma: no cover
            messagebox.showerror("Errore", f"Impossibile esportare i risultati:\n{exc}")
