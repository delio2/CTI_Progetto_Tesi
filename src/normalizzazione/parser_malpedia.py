"""Normalizzazione della tassonomia delle famiglie di Malpedia."""

import json
from pathlib import Path
from normalizzazione.io_snapshot import SnapshotNonValido
from normalizzazione.modelli import (
    MalwareFamily,
    RiferimentoGrezzo,
    RisultatoNormalizzazione,
    ThreatActor,
    calcola_slug,
    unisci_entita,
)

# La fonte identifica ogni famiglia con una chiave che antepone al nome la
# piattaforma su cui il codice gira: win.emotet, elf.mirai, apk.cerberus. La
# chiave è l'identificativo stabile della tassonomia e diventa quella dell'entità,
# come già accade con gli identificativi di ATT&CK. Il prefisso non viene invece
# tradotto in piattaforma: Malpedia scrive «win» dove ATT&CK scrive «Windows», e
# mescolare i due vocabolari darebbe a un solo campo due lingue diverse — per
# questo la chiave non viene mai spezzata, e non serve una costante che la separi.
#
# Non c'è nemmeno una costante FONTE come negli altri parser: quella serve a
# riempire il campo omonimo delle Observation, e Malpedia — come ATT&CK — è una
# tassonomia di riferimento che non osserva nulla.


def nomi_puliti(valori: list | None) -> list[str]:
    """Toglie gli spazi ai bordi e scarta le voci vuote."""
    # Serve davvero: fra i gruppi attribuiti la fonte scrive « Scarred Manticore»
    # e « Silent Chollima» con uno spazio iniziale, e senza questa pulizia
    # nascerebbero due gruppi distinti dallo stesso nome.
    return [voce.strip() for voce in (valori or []) if voce and voce.strip()]


def normalizza_famiglia(
    chiave: str, voce: dict, id_snapshot: str
) -> tuple[MalwareFamily, list[ThreatActor]] | None:
    """Traduce una voce della tassonomia nella famiglia e nei gruppi che la citano."""
    nome = (voce.get("common_name") or "").strip()
    if not nome:
        return None  # chi chiama conta la voce priva di nome fra gli scarti

    riferimento = RiferimentoGrezzo(
        id_snapshot=id_snapshot,
        # La chiave è già il percorso del record dentro il file, essendo la
        # tassonomia un dizionario indicizzato per identificativo.
        percorso_record=f"[{chiave}]",
        identificativo_naturale=chiave,
    )

    attribuita_a = nomi_puliti(voce.get("attribution"))
    alias = nomi_puliti(voce.get("alt_names"))
    famiglia = MalwareFamily(
        id=chiave,
        nome=nome,
        origini=["malpedia"],
        alias=alias,
        provenienze_alias={voce: [riferimento] for voce in alias},
        # La fonte censisce la famiglia anche quando non ne riporta una descrizione.
        descrizione=voce.get("description") or None,
        attribuita_a=attribuita_a,
        provenienze=[riferimento],
    )

    # I gruppi sono nominati, non censiti: Malpedia non assegna loro un
    # identificativo, quindi l'entità prende lo slug del nome come le altre
    # entità di nome libero. Che il gruppo qui nominato sia lo stesso già noto ad
    # ATT&CK è una corrispondenza, e la stabilisce il livello di correlazione.
    gruppi = [
        ThreatActor(
            id=calcola_slug(nome_gruppo),
            nome=nome_gruppo,
            origini=["malpedia"],
            provenienze=[riferimento],
        )
        for nome_gruppo in attribuita_a
    ]
    return famiglia, gruppi


def normalizza_file(percorso: Path, id_snapshot: str) -> RisultatoNormalizzazione:
    """Normalizza l'intera tassonomia di Malpedia."""
    with open(percorso, encoding="utf-8") as file_grezzo:
        contenuto = json.load(file_grezzo)

    prima = next(iter(contenuto.values()), None)
    if not isinstance(prima, dict) or "common_name" not in prima:
        raise SnapshotNonValido(
            f"{percorso}: non ha la forma della tassonomia di Malpedia"
        )

    famiglie: list[MalwareFamily] = []
    attori: dict[str, ThreatActor] = {}
    letti = 0
    scartati = 0

    for chiave, voce in contenuto.items():
        letti += 1
        tradotta = normalizza_famiglia(chiave, voce, id_snapshot)
        if tradotta is None:
            scartati += 1  # voce priva del nome comune
            continue

        famiglia, gruppi = tradotta
        famiglie.append(famiglia)
        for gruppo in gruppi:
            # Lo stesso gruppo è attribuito a più famiglie: ne resta una voce
            # sola, e la prima basta perché Malpedia non dichiara alias per i
            # gruppi. Il collegamento con ciascuna famiglia non si perde, perché
            # vive nel campo attribuita_a della famiglia.
            gia_visto = attori.get(gruppo.id)
            if gia_visto is None:
                attori[gruppo.id] = gruppo
            else:
                unisci_entita(gia_visto, gruppo)

    return RisultatoNormalizzazione(
        record_letti=letti,
        record_scartati=scartati,
        famiglie=famiglie,
        attori=list(attori.values()),
    )
