"""dns_analyzer.core – business‑logic pura senza GUI.

Classe principale: **DNSAnalyzer**.
Fornisce il metodo `.run()` che restituisce un `pandas.DataFrame` con i risultati
(comprensivi di severità e descrizioni best‑practice se abilitate).
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Tuple

import dns.resolver
import pandas as pd

__all__ = ["DNSAnalyzer"]


class DNSAnalyzer:
    """Esegue query DNS ed opzionali controlli di best‑practice."""

    DEFAULT_RECORD_TYPES: List[str] = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "CNAME",
        "TXT",
        "SPF",
        "DMARC",
        "DKIM",
        "BIMI",
        "SOA",
        "CAA",
    ]

    # ------------------------------------------------------------------ init
    def __init__(
        self,
        domains: List[str],
        *,
        dkim_selectors: List[str] | None = None,
        enable_best_practices: bool = False,
    ) -> None:
        if not domains:
            raise ValueError("La lista domini non può essere vuota.")

        self.domains = domains
        self.dkim_selectors = dkim_selectors or []
        self.enable_best_practices = enable_best_practices
        self.resolver = dns.resolver.Resolver()
        self.results: pd.DataFrame | None = None

    # ------------------------------------------------------------------ public
    def run(self, selected_record_types: List[str] | None = None) -> pd.DataFrame:
        """Esegue l'analisi e restituisce un DataFrame con le colonne:
        Domain, RecordType, Selector, Value, Issues, Severity.
        """
        record_types = selected_record_types or self.DEFAULT_RECORD_TYPES
        if self.enable_best_practices and not selected_record_types:
            record_types = ["SPF", "DMARC", "DKIM", "BIMI", "MX", "A", "AAAA", "NS"]

        out: List[Dict[str, str]] = []

        for domain in self.domains:
            for rtype in record_types:
                if rtype == "DKIM":
                    if not self.dkim_selectors:
                        out.append(_err(domain, "DKIM", "Nessun selettore DKIM fornito"))
                        continue
                    for selector in self.dkim_selectors:
                        _query_and_collect(
                            analyzer=self,
                            domain=domain,
                            query_domain=f"{selector}._domainkey.{domain}",
                            rtype="TXT",
                            logical_type="DKIM",
                            selector=selector,
                            out=out,
                        )
                elif rtype == "DMARC":
                    _query_and_collect(
                        analyzer=self,
                        domain=domain,
                        query_domain=f"_dmarc.{domain}",
                        rtype="TXT",
                        logical_type="DMARC",
                        out=out,
                    )
                elif rtype == "SPF":
                    _query_and_collect(
                        analyzer=self,
                        domain=domain,
                        query_domain=domain,
                        rtype="TXT",
                        logical_type="SPF",
                        out=out,
                    )
                elif rtype == "BIMI":
                    _query_and_collect(
                        analyzer=self,
                        domain=domain,
                        query_domain=f"default._bimi.{domain}",
                        rtype="TXT",
                        logical_type="BIMI",
                        out=out,
                    )
                else:
                    _query_and_collect(
                        analyzer=self,
                        domain=domain,
                        query_domain=domain,
                        rtype=rtype,
                        logical_type=rtype,
                        out=out,
                    )

        df = pd.DataFrame(out)
        if not df.empty:
            df.sort_values(
                by="Severity", key=lambda s: s.map(_severity_rank), ascending=False, inplace=True
            )
        self.results = df
        return df

# ------------------------------ helper interni -----------------------------

def _severity_rank(level: str) -> int:
    return {"CRITICAL": 4, "WARN": 3, "INFO": 2, "OK": 1, "": 0}.get(level, 0)


def _check_best_practices(record_type: str, values: List[str]) -> Tuple[str, str]:
    """Restituisce coppia (severity, descrizione)."""
    severity = "OK"
    issues: List[str] = []
    combined = " | ".join(values).lower()

    # SPF ------------------------------------------------------------------
    if record_type == "SPF":
        includes = combined.count("include:")
        if includes > 10:
            severity = "WARN"
            issues.append(f"SPF con {includes} include (possibili troppe query)")
        if "all" in combined and not any(s in combined for s in ("-all", "~all", "?all")):
            severity = max(severity, "WARN", key=_severity_rank)
            issues.append("SPF senza suffisso -all/~all/?all")
        if "include:*" in combined:
            severity = "CRITICAL"
            issues.append("SPF usa include:* (wildcard)")
        for val in values:
            if len(val) > 255:
                severity = max(severity, "WARN", key=_severity_rank)
                issues.append("Record SPF molto lungo (>255 caratteri)")

    # DMARC ----------------------------------------------------------------
    elif record_type == "DMARC":
        if "v=dmarc1" not in combined:
            severity = "CRITICAL"
            issues.append("DMARC non valido (manca v=DMARC1)")
        if "p=none" in combined:
            severity = max(severity, "WARN", key=_severity_rank)
            issues.append("DMARC policy=none (protezione debole)")
        if not any(k in combined for k in ("rua=", "ruf=")):
            severity = max(severity, "INFO", key=_severity_rank)
            issues.append("Nessun indirizzo di report (rua/ruf)")
        if len(values) > 1:
            severity = max(severity, "CRITICAL", key=_severity_rank)
            issues.append("DMARC duplicato (più record)")

    # DKIM ------------------------------------------------------------------
    elif record_type == "DKIM":
        if "p=" not in combined:
            severity = "CRITICAL"
            issues.append("DKIM non valido (manca p=)")
        if "k=rsa" not in combined:
            severity = max(severity, "WARN", key=_severity_rank)
            issues.append("Record DKIM senza k=rsa")
        for val in values:
            if "p=" in val:
                key_part = val.split("p=")[-1].split(";")[0].strip()
                if len(key_part) < 160:
                    severity = "CRITICAL"
                    issues.append("Chiave DKIM molto corta (<1024 bit?)")
                elif len(key_part) < 300:
                    severity = max(severity, "WARN", key=_severity_rank)
                    issues.append("Chiave DKIM <2048 bit")
        if len(values) > 1:
            severity = max(severity, "WARN", key=_severity_rank)
            issues.append("Selettore DKIM duplicato")

    # BIMI ------------------------------------------------------------------
    elif record_type == "BIMI":
        if "v=bimi1" not in combined:
            severity = "CRITICAL"
            issues.append("BIMI non valido (manca v=BIMI1)")
        if "l=" not in combined:
            severity = max(severity, "WARN", key=_severity_rank)
            issues.append("Campo l= mancante (logo SVG)")
        if "a=" not in combined:
            severity = max(severity, "WARN", key=_severity_rank)
            issues.append("Campo a= mancante (VMC/certificato)")
        if len(values) > 1:
            severity = max(severity, "WARN", key=_severity_rank)
            issues.append("Record BIMI duplicato")

    # MX --------------------------------------------------------------------
    elif record_type == "MX":
        if not values:
            severity = "CRITICAL"
            issues.append("Nessun record MX trovato")
        else:
            prio = [int(v.split()[0]) for v in values if v.split() and v.split()[0].isdigit()]
            if len(set(prio)) == 1 and len(prio) > 1:
                severity = max(severity, "WARN", key=_severity_rank)
                issues.append("Tutti i record MX hanno la stessa priorità")

    # A / AAAA --------------------------------------------------------------
    elif record_type in ("A", "AAAA"):
        for addr in values:
            try:
                if ipaddress.ip_address(addr).is_private:
                    severity = max(severity, "WARN", key=_severity_rank)
                    issues.append(f"Indirizzo {addr} privato")
            except ValueError:
                pass

    # NS --------------------------------------------------------------------
    elif record_type == "NS":
           if len(values) < 2:
            severity = max(severity, "WARN", key=_severity_rank)
            issues.append("Solo un nameserver configurato")

    # ------------------------------------------------------------------------
    return severity, "; ".join(issues)


# ---------------------------------------------------------------------------


def _query_and_collect(
    analyzer: "DNSAnalyzer",
    *,
    domain: str,
    query_domain: str,
    rtype: str,
    logical_type: str,
    out: List[Dict[str, str]],
    selector: str | None = None,
) -> None:
    """Esegue la query DNS e aggiunge il risultato alla lista *out*."""
    try:
        answer = analyzer.resolver.resolve(query_domain, rtype)
        records = [r.to_text() for r in answer]

        # Filtri di validazione specifici
        if logical_type == "SPF":
            records = [rec for rec in records if "v=spf1" in rec.lower()]
        elif logical_type == "DMARC":
            records = [rec for rec in records if "v=DMARC1" in rec]
        elif logical_type == "BIMI":
            records = [
                rec
                for rec in records
                if "v=BIMI1" in rec.upper() or "v=bimi1" in rec.lower()
            ]

        if analyzer.enable_best_practices:
            sev, details = _check_best_practices(logical_type, records)
        else:
            sev, details = ("", "")

        # Mancanza record valido → severity automatica
        if logical_type in {"SPF", "DMARC", "BIMI"} and not records:
            sev = "CRITICAL" if analyzer.enable_best_practices else ""
            details = f"Nessun record {logical_type} valido"
            records = [details]

        out.append(
            {
                "Domain": domain,
                "RecordType": logical_type,
                "Selector": selector or "",
                "Value": "|".join(records),
                "Issues": "" if sev in {"", "OK"} else details,
                "Severity": sev,
            }
        )

    except Exception as exc:
        sev = "CRITICAL" if analyzer.enable_best_practices else ""
        out.append(
            {
                "Domain": domain,
                "RecordType": logical_type,
                "Selector": selector or "",
                "Value": str(exc),
                "Issues": "Errore di lookup",
                "Severity": sev,
            }
        )


def _err(domain: str, logical_type: str, msg: str) -> Dict[str, str]:
    """Utility per produrre un dizionario d’errore coerente."""
    return {
        "Domain": domain,
        "RecordType": logical_type,
        "Selector": "",
        "Value": msg,
        "Issues": msg,
        "Severity": "CRITICAL",
    }
