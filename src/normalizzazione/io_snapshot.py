"""Lettura del manifest di raccolta e scrittura delle entità normalizzate."""

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from pydantic import BaseModel
from normalizzazione.modelli import SourceSnapshot

BLOCCO = 1024 * 1024  # quanto leggere per volta: il bundle ATT&CK pesa 42 MB


class ManifestNonValido(Exception):
    """Il manifest di raccolta non ha la forma attesa."""


# Una sola per tutti i parser, non una per fonte. Le tre erano classi distinte
# con lo stesso nome in file diversi, e chi legge il codice ha ragione ad
# aspettarsi che siano la stessa: un `except` scritto su una non intercettava le
# altre. Il messaggio dice sempre quale file e quale punto, quindi la fonte si
# riconosce da lì.
class SnapshotNonValido(Exception):
    """Il file acquisito non ha la forma attesa per la propria fonte."""


class IntegritaNonVerificata(Exception):
    """L'impronta del file non coincide con quella dichiarata nel manifest."""


class ManifestAssente(Exception):
    """Nella cartella delle acquisizioni non c'è alcun manifest."""


def trova_manifest(cartella_grezzi: Path) -> Path:
    """Il manifest più recente presente fra le acquisizioni."""
    # La data fa parte del nome del file e cambia a ogni raccolta: scriverla nel
    # codice significherebbe doverlo modificare dopo ogni acquisizione, e
    # dimenticarsene farebbe elaborare in silenzio uno snapshot superato.
    # L'ordinamento per nome coincide con quello cronologico, perché la data è
    # scritta nella forma anno-mese-giorno.
    manifest = sorted(cartella_grezzi.glob("manifest_*.json"))
    if not manifest:
        raise ManifestAssente(
            f"{cartella_grezzi}: nessun manifest, eseguire prima la raccolta"
        )
    return manifest[-1]


def leggi_manifest(percorso: Path) -> list[SourceSnapshot]:
    """Ricava dal manifest di raccolta un SourceSnapshot per ogni file grezzo."""
    with open(percorso, encoding="utf-8") as file_manifest:
        contenuto = json.load(file_manifest)

    if "sources" not in contenuto:
        raise ManifestNonValido(f"{percorso}: manca il campo 'sources'")

    return [
        SourceSnapshot(
            # threatfox_2026-08-19.json -> threatfox_2026-08-19. Non tutte le fonti
            # distribuiscono JSON: l'archivio di MalwareBazaar è un CSV.
            id=Path(voce["fileName"]).stem,
            fonte=voce["source"],
            url=voce["url"],
            acquisito_il=voce["fetchedAt"],
            nome_file=voce["fileName"],
            sha256=voce["sha256"],
            dimensione_byte=voce["sizeBytes"],
        )
        for voce in contenuto["sources"]
    ]


def calcola_impronta(percorso: Path) -> str:
    """Calcola l'impronta SHA-256 di un file, leggendolo a blocchi."""
    impronta = hashlib.sha256()
    with open(percorso, "rb") as file_binario:
        # iter con due argomenti richiama la funzione finché non restituisce il
        # secondo: qui legge blocchi finché il file non finisce, senza caricarlo
        # tutto in memoria.
        for blocco in iter(lambda: file_binario.read(BLOCCO), b""):
            impronta.update(blocco)
    return impronta.hexdigest()  # impronta in esadecimale


def calcola_impronte(cartella: Path, nomi_file: Iterable[str]) -> dict[str, str]:
    """Calcola l'impronta dei file indicati, mantenendo l'ordine ricevuto."""
    return {
        nome_file: calcola_impronta(cartella / nome_file) for nome_file in nomi_file
    }


def verifica_impronte(
    cartella: Path,
    impronte_attese: Mapping[str, str],
    nomi_attesi: Iterable[str] | None = None,
) -> None:
    """Verifica presenza, insieme e contenuto di un gruppo di file."""
    if nomi_attesi is not None:
        attesi = set(nomi_attesi)
        dichiarati = set(impronte_attese)
        if dichiarati != attesi:
            mancanti = sorted(attesi - dichiarati)
            inattesi = sorted(dichiarati - attesi)
            raise IntegritaNonVerificata(
                f"elenco dei file incoerente: mancanti={mancanti}, inattesi={inattesi}"
            )

    for nome_file, impronta_attesa in impronte_attese.items():
        percorso = cartella / nome_file
        if not percorso.is_file():
            raise IntegritaNonVerificata(f"{percorso}: file assente")
        impronta = calcola_impronta(percorso)
        if impronta != impronta_attesa:
            raise IntegritaNonVerificata(
                f"{nome_file}: impronta {impronta[:16]}... "
                f"invece di {impronta_attesa[:16]}... dichiarata"
            )


def verifica_integrita(cartella_grezzi: Path, snapshot: SourceSnapshot) -> None:
    """Confronta l'impronta del file con quella dichiarata alla raccolta."""
    # Gli esperimenti girano su uno snapshot congelato: normalizzare un file
    # diverso da quello raccolto invaliderebbe ogni misura successiva.
    impronta = calcola_impronta(cartella_grezzi / snapshot.nome_file)
    if impronta != snapshot.sha256:
        raise IntegritaNonVerificata(
            f"{snapshot.nome_file}: impronta {impronta[:16]}... "
            f"invece di {snapshot.sha256[:16]}... dichiarata nel manifest"
        )


def scrivi_jsonl(entita: list[BaseModel], percorso: Path) -> int:
    """Scrive le entità una per riga, riscrivendo il file da capo."""
    # La riscrittura integrale rende l'esecuzione ripetibile: rilanciarla non
    # accoda nulla alle esecuzioni precedenti.
    percorso.parent.mkdir(parents=True, exist_ok=True)  # crea data/processed/ se manca
    with open(percorso, "w", encoding="utf-8", newline="\n") as file_uscita:
        for elemento in entita:
            file_uscita.write(elemento.model_dump_json() + "\n")
    return len(entita)
