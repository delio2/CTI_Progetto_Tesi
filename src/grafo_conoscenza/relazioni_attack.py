"""Estrazione delle relazioni già stabilite da MITRE ATT&CK."""

import json
from pathlib import Path
from grafo_conoscenza.relazioni import RelazioneCalcolata, relazione
from normalizzazione.io_snapshot import verifica_integrita
from normalizzazione.modelli import SourceSnapshot
from normalizzazione.parser_mitre import (
    BundleNonValido,
    e_superato,
    leggi_identificativo,
)

# La normalizzazione traduce questi tipi STIX; la stessa scelta vale qui, così
# gli archi non possono puntare a nodi che il grafo non contiene.
ETICHETTA_PER_TIPO_STIX = {
    "intrusion-set": "ThreatActor",
    "malware": "MalwareFamily",
    "tool": "MalwareFamily",
    "attack-pattern": "AttackTechnique",
}

ORIGINI_AMMESSE = ("intrusion-set", "malware", "tool")
DESTINAZIONI_AMMESSE = ("attack-pattern", "malware", "tool")
FONTE_ATTACK = "MITRE ATT&CK"


class SnapshotAttackMancante(Exception):
    """Lo snapshot normalizzato non contiene il bundle MITRE ATT&CK."""


def trova_bundle_attack(
    cartella_grezzi: Path, snapshot_normalizzati: list[SourceSnapshot]
) -> Path:
    """Trova il bundle esatto da cui sono state normalizzate le entità ATT&CK."""
    for snapshot in snapshot_normalizzati:
        if snapshot.fonte == FONTE_ATTACK:
            verifica_integrita(cartella_grezzi, snapshot)
            return cartella_grezzi / snapshot.nome_file
    raise SnapshotAttackMancante(
        f"lo snapshot normalizzato non dichiara la fonte {FONTE_ATTACK!r}"
    )


def _tipo_stix(riferimento: str) -> str:
    """Ricava il tipo dall'identificatore STIX, nella forma tipo--uuid."""
    return riferimento.split("--", 1)[0]


def leggi_entita_tradotte(bundle: dict) -> dict[str, tuple[str, str]]:
    """Mappa ogni identificatore STIX all'etichetta e all'identificativo di ATT&CK."""
    # Applica gli stessi criteri di scarto della normalizzazione: un oggetto
    # ritirato o privo di identificativo non è diventato un nodo, quindi un arco
    # che lo raggiungesse resterebbe sospeso.
    tradotte = {}
    for oggetto in bundle["objects"]:
        tipo_stix = oggetto.get("type")
        if tipo_stix not in ETICHETTA_PER_TIPO_STIX or e_superato(oggetto):
            continue
        identificativo = leggi_identificativo(oggetto)
        if identificativo:
            tradotte[oggetto["id"]] = (
                ETICHETTA_PER_TIPO_STIX[tipo_stix],
                identificativo,
            )
    return tradotte


def _leggi_bundle(percorso: Path) -> dict:
    """Legge un bundle STIX e ne verifica la struttura minima."""
    with open(percorso, encoding="utf-8") as file_grezzo:
        bundle = json.load(file_grezzo)
    if bundle.get("type") != "bundle" or "objects" not in bundle:
        raise BundleNonValido(f"{percorso}: non è un bundle STIX")
    return bundle


def genera_sostituzioni_tecniche(percorso: Path) -> dict[str, str]:
    """Mappa gli ID di tecniche revocate sulle sostitute attive indicate da ATT&CK."""
    bundle = _leggi_bundle(percorso)
    per_id_stix = {
        oggetto["id"]: oggetto for oggetto in bundle["objects"] if "id" in oggetto
    }
    sostituzioni_stix = {}

    for relazione_stix in bundle["objects"]:
        if relazione_stix.get("type") != "relationship":
            continue
        if relazione_stix.get("relationship_type") != "revoked-by" or e_superato(
            relazione_stix
        ):
            continue

        origine = relazione_stix.get("source_ref")
        destinazione = relazione_stix.get("target_ref")
        oggetto_origine = per_id_stix.get(origine)
        oggetto_destinazione = per_id_stix.get(destinazione)
        if not oggetto_origine or not oggetto_destinazione:
            raise BundleNonValido(
                f"{percorso}: relazione revoked-by con un estremo assente"
            )
        if (
            oggetto_origine.get("type") != "attack-pattern"
            or oggetto_destinazione.get("type") != "attack-pattern"
        ):
            continue
        if origine in sostituzioni_stix and sostituzioni_stix[origine] != destinazione:
            raise BundleNonValido(f"{percorso}: tecnica revocata con più sostituzioni")
        sostituzioni_stix[origine] = destinazione

    sostituzioni = {}
    for origine in sostituzioni_stix:
        corrente = origine
        visitati = set()
        while corrente in sostituzioni_stix:
            if corrente in visitati:
                raise BundleNonValido(f"{percorso}: ciclo nelle relazioni revoked-by")
            visitati.add(corrente)
            corrente = sostituzioni_stix[corrente]

        oggetto_origine = per_id_stix[origine]
        oggetto_corrente = per_id_stix[corrente]
        id_origine = leggi_identificativo(oggetto_origine)
        id_corrente = leggi_identificativo(oggetto_corrente)
        if id_origine and id_corrente and not e_superato(oggetto_corrente):
            sostituzioni[id_origine] = id_corrente
    return sostituzioni


def genera_uses(percorso: Path) -> list[RelazioneCalcolata]:
    """Ricava gli archi USES dagli oggetti relationship del bundle."""
    # La normalizzazione scarta di proposito gli oggetti relationship, perché
    # costruire archi non le compete: il file grezzo viene quindi riaperto qui.
    bundle = _leggi_bundle(percorso)

    tradotte = leggi_entita_tradotte(bundle)
    relazioni = []

    for oggetto in bundle["objects"]:
        if oggetto.get("type") != "relationship":
            continue
        if oggetto.get("relationship_type") != "uses" or e_superato(oggetto):
            continue

        origine = oggetto["source_ref"]
        destinazione = oggetto["target_ref"]
        # Restano fuori le relazioni che coinvolgono tipi non tradotti dal
        # modello. ATT&CK usa invece USES sia verso tecniche sia verso malware
        # e strumenti: i tre casi hanno nodi canonici e vanno tutti conservati.
        if _tipo_stix(origine) not in ORIGINI_AMMESSE:
            continue
        if _tipo_stix(destinazione) not in DESTINAZIONI_AMMESSE:
            continue
        if origine not in tradotte or destinazione not in tradotte:
            continue

        etichetta_origine, id_origine = tradotte[origine]
        etichetta_destinazione, id_destinazione = tradotte[destinazione]
        relazioni.append(
            relazione(
                "USES",
                etichetta_origine,
                id_origine,
                etichetta_destinazione,
                id_destinazione,
                oggetto["id"],
                "relazione già presente in ATT&CK",
                f"{origine} -> {destinazione}",
            )
        )
    return relazioni
