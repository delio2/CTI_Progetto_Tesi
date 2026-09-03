"""Coerenza fra i file prodotti da normalizzazione e correlazione."""

import json
from pathlib import Path

from normalizzazione.io_snapshot import IntegritaNonVerificata, verifica_impronte


NOME_MANIFEST_NORMALIZZAZIONE = "manifest_normalizzazione.json"
NOME_MANIFEST_CORRELAZIONE = "manifest_correlazione.json"
NOME_FILE_RELAZIONI = "relazioni.jsonl"


class ElaborazioneIncoerente(Exception):
    """I file elaborati non appartengono allo stesso snapshot verificato."""


def _leggi_oggetto_json(percorso: Path) -> dict:
    if not percorso.is_file():
        raise ElaborazioneIncoerente(f"{percorso}: file assente")
    try:
        with open(percorso, encoding="utf-8") as file_manifest:
            contenuto = json.load(file_manifest)
    except (OSError, json.JSONDecodeError) as errore:
        raise ElaborazioneIncoerente(f"{percorso}: JSON non valido") from errore
    if not isinstance(contenuto, dict):
        raise ElaborazioneIncoerente(f"{percorso}: atteso un oggetto JSON")
    return contenuto


def _leggi_impronte(contenuto: dict, campo: str, percorso: Path) -> dict[str, str]:
    impronte = contenuto.get(campo)
    if not isinstance(impronte, dict) or not all(
        isinstance(nome, str) and isinstance(impronta, str)
        for nome, impronta in impronte.items()
    ):
        raise ElaborazioneIncoerente(
            f"{percorso}: campo {campo!r} assente o non valido"
        )
    return impronte


def verifica_normalizzazione(cartella: Path, nomi_file: tuple[str, ...]) -> dict:
    """Valida il manifest e le impronte delle entità normalizzate."""
    percorso = cartella / NOME_MANIFEST_NORMALIZZAZIONE
    manifest = _leggi_oggetto_json(percorso)
    impronte = _leggi_impronte(manifest, "impronte_file", percorso)
    try:
        verifica_impronte(cartella, impronte, nomi_file)
    except IntegritaNonVerificata as errore:
        raise ElaborazioneIncoerente(str(errore)) from errore
    return manifest


def riferimento_normalizzazione(manifest: dict) -> dict:
    """Riduce il manifest ai dati necessari a legare la correlazione agli input."""
    return {
        "eseguita_il": manifest.get("eseguita_il"),
        "impronte_file": manifest["impronte_file"],
    }


def verifica_correlazione(cartella: Path, nomi_file: tuple[str, ...]) -> dict:
    """Controlla tutti gli input prima che il grafo possa essere cancellato."""
    normalizzazione = verifica_normalizzazione(cartella, nomi_file)
    percorso = cartella / NOME_MANIFEST_CORRELAZIONE
    manifest = _leggi_oggetto_json(percorso)

    riferimento = manifest.get("normalizzazione")
    if not isinstance(riferimento, dict):
        raise ElaborazioneIncoerente(
            f"{percorso}: manca il riferimento alla normalizzazione"
        )
    impronte_input = _leggi_impronte(riferimento, "impronte_file", percorso)
    if impronte_input != normalizzazione["impronte_file"]:
        raise ElaborazioneIncoerente(
            "la correlazione non è stata calcolata sui file normalizzati correnti"
        )

    uscita = manifest.get("relazioni")
    if not isinstance(uscita, dict) or uscita.get("nome_file") != NOME_FILE_RELAZIONI:
        raise ElaborazioneIncoerente(
            f"{percorso}: riferimento al file delle relazioni non valido"
        )
    impronta_relazioni = uscita.get("sha256")
    if not isinstance(impronta_relazioni, str):
        raise ElaborazioneIncoerente(
            f"{percorso}: manca l'impronta del file delle relazioni"
        )
    try:
        verifica_impronte(
            cartella,
            {NOME_FILE_RELAZIONI: impronta_relazioni},
            (NOME_FILE_RELAZIONI,),
        )
    except IntegritaNonVerificata as errore:
        raise ElaborazioneIncoerente(str(errore)) from errore
    return manifest
