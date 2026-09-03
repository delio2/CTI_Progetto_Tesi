"""Calcolo di tutte le relazioni fra le entità normalizzate."""

import json
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from grafo_conoscenza.integrita import (
    NOME_FILE_RELAZIONI,
    riferimento_normalizzazione,
    verifica_normalizzazione,
)
from grafo_conoscenza.relazioni import (
    RelazioneCalcolata,
    genera_corresponds_to_alias,
    genera_corresponds_to_impronta,
    genera_has_host,
    genera_indicates,
    genera_mentions,
    genera_uses_attribuzione,
    itera_derived_from,
    itera_observes,
    itera_sample_of,
)
from grafo_conoscenza.relazioni_attack import (
    genera_sostituzioni_tecniche,
    genera_uses,
    trova_bundle_attack,
)
from normalizzazione.io_snapshot import calcola_impronta
from normalizzazione.modelli import (
    AttackTechnique,
    Indicator,
    MalwareFamily,
    MalwareSample,
    Observation,
    SourceSnapshot,
    ThreatActor,
    ThreatReport,
)

CARTELLA_GREZZI = Path("data/raw")
CARTELLA_NORMALIZZATI = Path("data/processed")

# Il file da cui rileggere ciascun tipo di entità, con il modello che lo valida.
MODELLO_PER_FILE = {
    "source_snapshot.jsonl": SourceSnapshot,
    "indicator.jsonl": Indicator,
    "observation.jsonl": Observation,
    "malware_sample.jsonl": MalwareSample,
    "malware_family.jsonl": MalwareFamily,
    "threat_actor.jsonl": ThreatActor,
    "attack_technique.jsonl": AttackTechnique,
    "threat_report.jsonl": ThreatReport,
}


class EntitaMancanti(Exception):
    """Manca un file di entità normalizzate: la normalizzazione non è stata eseguita."""


def leggi_jsonl(percorso: Path, modello: type[BaseModel]) -> list:
    """Rilegge un file di entità normalizzate, convalidandole con il loro modello."""
    if not percorso.exists():
        raise EntitaMancanti(f"{percorso}: eseguire prima la normalizzazione")
    entita = []
    with open(percorso, encoding="utf-8") as file_entita:
        for riga in file_entita:
            entita.append(modello.model_validate_json(riga))
    return entita


def leggi_entita(cartella: Path) -> dict[str, list]:
    """Rilegge tutte le entità prodotte dalla normalizzazione."""
    return {
        nome_file: leggi_jsonl(cartella / nome_file, modello)
        for nome_file, modello in MODELLO_PER_FILE.items()
    }


def deduplica(
    relazioni: Iterable[RelazioneCalcolata],
) -> list[RelazioneCalcolata]:
    """Unisce gli archi uguali senza perdere i loro supporti indipendenti."""
    uniche = {}
    for relazione in relazioni:
        chiave = [
            relazione.tipo_relazione,
            relazione.tipo_origine,
            relazione.id_origine,
            relazione.tipo_destinazione,
            relazione.id_destinazione,
        ]
        # Due record dello stesso snapshot sono due provenienze distinte e
        # diventano archi DERIVED_FROM distinti anche quando gli estremi coincidono.
        if relazione.tipo_relazione == "DERIVED_FROM":
            chiave.extend(
                (relazione.percorso_record, relazione.identificativo_naturale)
            )
        chiave = tuple(chiave)

        esistente = uniche.get(chiave)
        if esistente is None:
            uniche[chiave] = relazione
            continue

        affermazioni = set(
            zip(esistente.supporti, esistente.regole, esistente.evidenze)
        )
        affermazioni.update(
            zip(relazione.supporti, relazione.regole, relazione.evidenze)
        )
        ordinate = sorted(affermazioni)
        esistente.supporti = [voce[0] for voce in ordinate]
        esistente.regole = [voce[1] for voce in ordinate]
        esistente.evidenze = [voce[2] for voce in ordinate]
    return list(uniche.values())


def itera_relazioni_dirette(entita: dict[str, list]):
    """Produce gli archi già univoci senza conservarli tutti in memoria."""
    for nome_file, elenco in entita.items():
        if nome_file == "source_snapshot.jsonl":
            continue  # lo snapshot è destinazione di DERIVED_FROM, non origine
        etichetta = MODELLO_PER_FILE[nome_file].__name__
        yield from itera_derived_from(elenco, etichetta)

    osservazioni = entita["observation.jsonl"]
    yield from itera_observes(osservazioni)
    yield from itera_sample_of(
        entita["malware_sample.jsonl"], entita["malware_family.jsonl"]
    )


def itera_relazioni_semantiche(
    entita: dict[str, list],
    percorso_attack: Path,
    sostituzioni_tecniche: dict[str, str],
):
    """Applica le regole i cui archi possono ricevere più supporti."""
    indicatori = entita["indicator.jsonl"]
    osservazioni = entita["observation.jsonl"]
    campioni = entita["malware_sample.jsonl"]
    famiglie = entita["malware_family.jsonl"]
    attori = entita["threat_actor.jsonl"]
    tecniche = entita["attack_technique.jsonl"]
    report = entita["threat_report.jsonl"]
    fonte_per_snapshot = {
        snapshot.id: snapshot.fonte for snapshot in entita["source_snapshot.jsonl"]
    }

    yield from genera_has_host(osservazioni)
    yield from genera_indicates(osservazioni, famiglie)
    yield from genera_corresponds_to_impronta(indicatori, campioni)
    yield from genera_corresponds_to_alias(
        famiglie, "MalwareFamily", fonte_per_snapshot
    )
    yield from genera_corresponds_to_alias(attori, "ThreatActor", fonte_per_snapshot)
    yield from genera_uses_attribuzione(famiglie, attori, fonte_per_snapshot)
    yield from genera_mentions(
        report,
        indicatori,
        famiglie,
        attori,
        tecniche,
        sostituzioni_tecniche,
    )
    yield from genera_uses(percorso_attack)


def scrivi_relazioni(relazioni: Iterable[RelazioneCalcolata], percorso: Path) -> dict:
    """Scrive atomicamente le relazioni e ne calcola il riepilogo."""
    percorso.parent.mkdir(parents=True, exist_ok=True)
    temporaneo = percorso.with_suffix(percorso.suffix + ".tmp")
    conteggi = Counter()
    supporti_per_tipo = Counter()
    regole = Counter()

    try:
        with open(temporaneo, "w", encoding="utf-8", newline="\n") as file_uscita:
            for arco in relazioni:
                file_uscita.write(arco.model_dump_json() + "\n")
                conteggi[arco.tipo_relazione] += 1
                supporti_per_tipo[arco.tipo_relazione] += len(arco.supporti)
                regole.update(arco.regole)
        temporaneo.replace(percorso)
    finally:
        temporaneo.unlink(missing_ok=True)

    return {
        "archi_totali": sum(conteggi.values()),
        "supporti_totali": sum(supporti_per_tipo.values()),
        "archi_per_tipo": dict(conteggi),
        "supporti_per_tipo": dict(supporti_per_tipo),
        "supporti_per_regola": dict(regole),
    }


def esegui(
    cartella_grezzi: Path = CARTELLA_GREZZI,
    cartella_normalizzati: Path = CARTELLA_NORMALIZZATI,
) -> dict[str, int]:
    """Calcola le relazioni e le scrive accanto alle entità normalizzate."""
    manifest_normalizzazione = verifica_normalizzazione(
        cartella_normalizzati, tuple(MODELLO_PER_FILE)
    )
    entita = leggi_entita(cartella_normalizzati)
    percorso_attack = trova_bundle_attack(
        cartella_grezzi, entita["source_snapshot.jsonl"]
    )
    sostituzioni_tecniche = genera_sostituzioni_tecniche(percorso_attack)

    def tutte_le_relazioni():
        yield from itera_relazioni_dirette(entita)
        yield from deduplica(
            itera_relazioni_semantiche(entita, percorso_attack, sostituzioni_tecniche)
        )

    percorso_relazioni = cartella_normalizzati / NOME_FILE_RELAZIONI
    riepilogo = scrivi_relazioni(tutte_le_relazioni(), percorso_relazioni)
    riepilogo = {
        "eseguita_il": datetime.now(timezone.utc).isoformat(),
        **riepilogo,
        "normalizzazione": riferimento_normalizzazione(manifest_normalizzazione),
        "relazioni": {
            "nome_file": NOME_FILE_RELAZIONI,
            "sha256": calcola_impronta(percorso_relazioni),
        },
    }
    (cartella_normalizzati / "manifest_correlazione.json").write_text(
        json.dumps(riepilogo, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return Counter(riepilogo["archi_per_tipo"])


if __name__ == "__main__":
    conteggi = esegui()
    for tipo_relazione, quante in sorted(conteggi.items()):
        print(f"{tipo_relazione:20} {quante:7}")
    print(f"{'TOTALE':20} {sum(conteggi.values()):7}")
