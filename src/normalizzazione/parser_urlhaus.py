"""Normalizzazione dello snapshot di URLhaus."""

import json
from datetime import datetime
from pathlib import Path
from normalizzazione.io_snapshot import SnapshotNonValido
from normalizzazione.modelli import (
    Indicator,
    Observation,
    RiferimentoGrezzo,
    RisultatoNormalizzazione,
    calcola_id_indicator,
    calcola_id_observation,
    converti_data_utc,
    indicatore_host_da_url,
    unisci_entita,
)
from normalizzazione.vocabolari import TipoIndicatore, uniforma_valore

FONTE = "URLhaus"

# La fonte scrive le date come le sorelle di abuse.ch ma vi aggiunge il fuso in
# chiaro: «2026-08-26 09:05:27 UTC». Il fuso è quello che il modello canonico già
# assume per tutte, quindi si toglie il suffisso e si riusa la conversione comune
# invece di scriverne una seconda che interpreterebbe le date a modo proprio.
SUFFISSO_FUSO = " UTC"


def converti_data(testo: str | None) -> datetime | None:
    """Converte una data di URLhaus, che dichiara il fuso in coda al testo."""
    if not testo:
        return None
    if not testo.endswith(SUFFISSO_FUSO):
        raise SnapshotNonValido(f"data di URLhaus in forma inattesa: {testo!r}")
    return converti_data_utc(testo[: -len(SUFFISSO_FUSO)])


def osservazione_per(
    record: dict, id_indicatore: str, riferimento: RiferimentoGrezzo
) -> Observation:
    """L'osservazione che URLhaus fa dell'indicatore, con quel che ne dichiara."""
    return Observation(
        id=calcola_id_observation(riferimento),
        id_indicator=id_indicatore,
        fonte=FONTE,
        tipo_minaccia=record.get("threat"),
        prima_osservazione=converti_data(record.get("dateadded")),
        # La fonte non registra l'ultima osservazione ma l'ultima volta che
        # l'URL ha risposto: per un indicatore ancora attivo le due cose
        # coincidono, per uno spento è comunque l'ultima verifica riuscita.
        ultima_osservazione=converti_data(record.get("last_online")),
        segnalatore=record.get("reporter"),
        etichette=list(record.get("tags") or []),
        indicatore_attivo=record.get("url_status") == "online",
        riferimenti=[record["urlhaus_link"]] if record.get("urlhaus_link") else [],
        provenienze=[riferimento],
    )


def normalizza_record(
    record: dict, identificativo: str, id_snapshot: str
) -> tuple[list[Indicator], list[Observation]]:
    """Traduce un record di URLhaus nell'URL segnalato e nell'host che lo ospita."""
    riferimento = RiferimentoGrezzo(
        id_snapshot=id_snapshot,
        # Come per ThreatFox, la posizione del record è il suo identificativo:
        # regge alle riscritture dell'archivio, l'indice no.
        percorso_record=f"[{identificativo}]",
        identificativo_naturale=identificativo,
    )

    valore = uniforma_valore(TipoIndicatore.URL, record["url"])
    url = Indicator(
        id=calcola_id_indicator(TipoIndicatore.URL, valore),
        tipo=TipoIndicatore.URL,
        valore=valore,
        provenienze=[riferimento],
    )
    indicatori = [url]
    osservazioni = [osservazione_per(record, url.id, riferimento)]

    host = indicatore_host_da_url(valore, riferimento)
    if host is not None:
        indicatori.append(host)
        osservazioni[0].id_host_derivato = host.id

    return indicatori, osservazioni


# La fonte distribuisce l'archivio nella stessa forma di ThreatFox: un dizionario
# che a ogni identificativo associa un elenco con dentro il solo record.
def normalizza_file(percorso: Path, id_snapshot: str) -> RisultatoNormalizzazione:
    """Normalizza un intero snapshot di URLhaus."""
    with open(percorso, encoding="utf-8") as file_grezzo:
        contenuto = json.load(file_grezzo)

    if not isinstance(next(iter(contenuto.values()), None), list):
        raise SnapshotNonValido(f"{percorso}: non ha la forma dell'archivio di URLhaus")

    indicatori: dict[str, Indicator] = {}
    osservazioni: list[Observation] = []
    letti = 0

    for identificativo, voce in contenuto.items():
        if len(voce) != 1:
            raise SnapshotNonValido(
                f"{percorso}: l'identificativo {identificativo} porta "
                f"{len(voce)} record, ne serve uno"
            )

        letti += 1
        trovati, viste = normalizza_record(voce[0], identificativo, id_snapshot)
        for indicatore in trovati:
            gia_visto = indicatori.get(indicatore.id)
            if gia_visto is None:
                indicatori[indicatore.id] = indicatore
            else:
                unisci_entita(gia_visto, indicatore)
        osservazioni.extend(viste)

    # Nessuno scarto possibile: la fonte distribuisce un solo tipo di indicatore,
    # l'URL, che lo schema canonico rappresenta. Dove le altre fonti scartano è
    # perché dichiarano tipi che il modello non prevede.
    return RisultatoNormalizzazione(
        record_letti=letti,
        record_scartati=0,
        indicatori=list(indicatori.values()),
        osservazioni=osservazioni,
    )
