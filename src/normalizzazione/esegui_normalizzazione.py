"""Esecuzione della normalizzazione su un intero snapshot di raccolta."""

import json
from datetime import datetime, timezone
from pathlib import Path
from normalizzazione import (
    parser_malpedia,
    parser_malwarebazaar,
    parser_mitre,
    parser_otx,
    parser_threatfox,
    parser_urlhaus,
)
from normalizzazione.io_snapshot import (
    calcola_impronte,
    leggi_manifest,
    scrivi_jsonl,
    trova_manifest,
    verifica_integrita,
)
from normalizzazione.modelli import (
    RisultatoNormalizzazione,
    SourceSnapshot,
    deduplica_entita,
    unisci_entita,
)

CARTELLA_GREZZI = Path("data/raw")
CARTELLA_NORMALIZZATI = Path("data/processed")

PARSER_PER_FONTE = {
    "ThreatFox": parser_threatfox,
    "MalwareBazaar": parser_malwarebazaar,
    "URLhaus": parser_urlhaus,
    "AlienVault OTX (subscribed)": parser_otx,
    "MITRE ATT&CK": parser_mitre,
    "Malpedia": parser_malpedia,
}

FILE_PER_TIPO = {
    "indicatori": "indicator.jsonl",
    "osservazioni": "observation.jsonl",
    "campioni": "malware_sample.jsonl",
    "famiglie": "malware_family.jsonl",
    "attori": "threat_actor.jsonl",
    "tecniche": "attack_technique.jsonl",
    "report": "threat_report.jsonl",
}


class FonteSconosciuta(Exception):
    """Il manifest dichiara una fonte per cui non esiste un parser."""


def unisci_per_identificatore(entita: list) -> list:
    """Riduce a una voce sola le entità che condividono l'identificatore."""
    # Non è una correlazione. Per gli indicatori e i campioni l'identificatore è
    # calcolato dal contenuto, quindi due voci che coincidono sono per costruzione
    # la stessa entità e tenere la prima non perde nulla. Per le famiglie e gli
    # attori di origine operativa l'identificatore è invece lo slug del nome, e
    # due fonti possono attribuire allo stesso nome alias diversi: OTX non ne
    # dichiara nessuno, ThreatFox sì, e tenere la prima voce cancellerebbe gli
    # alias dell'altra a seconda dell'ordine in cui il manifest elenca le fonti.
    # Le osservazioni non sono toccate: il loro identificatore include il record
    # di origine ed è quindi già unico.
    unite = {}
    for elemento in entita:
        gia_vista = unite.get(elemento.id)
        if gia_vista is None:
            unite[elemento.id] = elemento
        else:
            unisci_entita(gia_vista, elemento)

    risultato = list(unite.values())
    for elemento in risultato:
        deduplica_entita(elemento)
    return risultato


def normalizza_snapshot(
    cartella_grezzi: Path, snapshot: list[SourceSnapshot]
) -> tuple[RisultatoNormalizzazione, dict]:
    """Applica a ogni file il parser della sua fonte e riunisce i risultati."""
    # Restituisce anche i conteggi per fonte, che servono a misurare la quota di
    # record normalizzati.
    complessivo = RisultatoNormalizzazione()
    conteggi = {}

    for voce in snapshot:
        parser = PARSER_PER_FONTE.get(voce.fonte)
        if parser is None:
            raise FonteSconosciuta(f"nessun parser per la fonte {voce.fonte!r}")

        verifica_integrita(cartella_grezzi, voce)
        risultato = parser.normalizza_file(cartella_grezzi / voce.nome_file, voce.id)

        complessivo.record_letti += risultato.record_letti
        complessivo.record_scartati += risultato.record_scartati

        prodotte = {}
        for attributo in FILE_PER_TIPO:
            entita = getattr(risultato, attributo)  # legge il campo dal suo nome
            getattr(complessivo, attributo).extend(entita)
            if entita:
                prodotte[attributo] = len(entita)

        conteggi[voce.id] = {
            "fonte": voce.fonte,
            "record_letti": risultato.record_letti,
            "record_scartati": risultato.record_scartati,
            "entita_prodotte": prodotte,
        }

    return complessivo, conteggi


def esegui(
    cartella_grezzi: Path = CARTELLA_GREZZI,
    cartella_uscita: Path = CARTELLA_NORMALIZZATI,
    nome_manifest: str | None = None,
) -> dict[str, int]:
    """Normalizza lo snapshot descritto dal manifest e ne scrive le entità."""
    percorso_manifest = (
        cartella_grezzi / nome_manifest
        if nome_manifest
        else trova_manifest(cartella_grezzi)
    )
    snapshot = leggi_manifest(percorso_manifest)
    complessivo, conteggi = normalizza_snapshot(cartella_grezzi, snapshot)

    scritti = {
        "source_snapshot.jsonl": scrivi_jsonl(
            snapshot, cartella_uscita / "source_snapshot.jsonl"
        )
    }
    for attributo, nome_file in FILE_PER_TIPO.items():
        entita = unisci_per_identificatore(getattr(complessivo, attributo))
        scritti[nome_file] = scrivi_jsonl(entita, cartella_uscita / nome_file)

    riepilogo = {
        "eseguita_il": datetime.now(timezone.utc).isoformat(),
        "record_letti": complessivo.record_letti,
        "record_scartati": complessivo.record_scartati,
        "entita_scritte": scritti,
        "impronte_file": calcola_impronte(cartella_uscita, scritti),
        "per_fonte": conteggi,
    }
    (cartella_uscita / "manifest_normalizzazione.json").write_text(
        json.dumps(riepilogo, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return scritti


if __name__ == "__main__":
    scritti = esegui()
    for nome_file, quante in scritti.items():
        print(f"{nome_file:28} {quante:7}")
    print(f"{'TOTALE':28} {sum(scritti.values()):7}")
