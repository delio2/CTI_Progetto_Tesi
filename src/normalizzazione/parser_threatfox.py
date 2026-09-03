"""Normalizzazione dello snapshot di ThreatFox."""

import json
from pathlib import Path
from normalizzazione.io_snapshot import SnapshotNonValido
from normalizzazione.modelli import (
    Indicator,
    MalwareFamily,
    Observation,
    RiferimentoGrezzo,
    RisultatoNormalizzazione,
    calcola_id_indicator,
    calcola_id_observation,
    calcola_slug,
    converti_data_utc,
    indicatore_host_da_url,
    unisci_entita,
)
from normalizzazione.vocabolari import (
    TipoIndicatore,
    ValoreIndicatoreNonValido,
    mappa_tipo_threatfox,
    uniforma_valore,
)

FONTE = "ThreatFox"


def separa_elenco(testo: str | None) -> list[str]:
    """Divide un elenco, che la fonte scrive come un'unica stringa separata da virgole."""
    # Vale per gli alias della famiglia e per le etichette. Separarli è la base
    # della regola di correlazione fra famiglie: uniti, il confronto con i nomi
    # dichiarati da ATT&CK non avrebbe corrispondenze.
    if not testo:
        return []
    return [voce.strip() for voce in testo.split(",") if voce.strip()]


# Dove la famiglia non è stata identificata, la fonte non lascia il campo vuoto:
# scrive «Unknown malware» o una variante per categoria. Preso alla lettera, il
# segnaposto raggrupperebbe indicatori che non hanno altro in comune che l'essere
# ignoti. È la stessa convenzione che MalwareBazaar esprime con "n/a".
PREFISSO_FAMIGLIA_IGNOTA = "unknown"


def leggi_famiglia(record: dict) -> str | None:
    """Il nome della famiglia, o None quando la fonte dichiara di non conoscerla."""
    # Il criterio guarda `malware` e non il nome leggibile: è la forma controllata
    # dalla fonte, mentre un nome vero potrebbe cominciare per «Unknown».
    if (record.get("malware") or "").startswith(PREFISSO_FAMIGLIA_IGNOTA):
        return None
    return (record.get("malware_printable") or "").strip() or None


# Restituisce None quando la fonte dichiara un tipo che lo schema canonico non
# rappresenta: chi chiama lo conta fra gli scarti anziché interrompersi, come già
# fa il parser di OTX davanti allo stesso caso.
def normalizza_record(
    record: dict, identificativo: str, id_snapshot: str
) -> tuple[Indicator, Observation, MalwareFamily | None, Indicator | None] | None:
    """Traduce un record di ThreatFox in indicatore, osservazione e famiglia."""
    tipo = mappa_tipo_threatfox(record["ioc_type"])
    if tipo is None:
        return None

    riferimento = RiferimentoGrezzo(
        id_snapshot=id_snapshot,
        # La posizione del record è il suo stesso identificativo: è un
        # riferimento più stabile dell'indice, che dipende dall'ordine.
        percorso_record=f"[{identificativo}]",
        identificativo_naturale=identificativo,
    )

    if record["ioc_type"] == "ip:port":
        # L'indicatore è l'indirizzo; la porta descrive ciò che vi è stato
        # osservato. Uniti non combacerebbero con le altre fonti, che riportano
        # il solo indirizzo.
        valore, porta_grezza = record["ioc_value"].rsplit(
            ":", 1
        )  # divide sull'ultimo ":"
        try:
            numero_porta = int(porta_grezza)
        except ValueError:
            numero_porta = 0
        porta = numero_porta if 1 <= numero_porta <= 65535 else None
    else:
        valore, porta = record["ioc_value"], None

    try:
        valore = uniforma_valore(tipo, valore)
    except ValoreIndicatoreNonValido:
        return None
    nome_famiglia = leggi_famiglia(record)
    alias = separa_elenco(record.get("malware_alias"))

    indicatore = Indicator(
        id=calcola_id_indicator(tipo, valore),
        tipo=tipo,
        valore=valore,
        provenienze=[riferimento],
    )
    osservazione = Observation(
        id=calcola_id_observation(riferimento),
        id_indicator=indicatore.id,
        fonte=FONTE,
        tipo_minaccia=record.get("threat_type"),
        porta=porta,
        famiglia_dichiarata=nome_famiglia,
        livello_confidenza=record.get("confidence_level"),
        prima_osservazione=converti_data_utc(record.get("first_seen_utc")),
        ultima_osservazione=converti_data_utc(record.get("last_seen_utc")),
        segnalatore=record.get("reporter"),
        etichette=separa_elenco(record.get("tags")),
        compromesso=record.get("is_compromised"),  # host di terzi violato
        riferimenti=[record["reference"]] if record.get("reference") else [],
        provenienze=[riferimento],
    )
    host = (
        indicatore_host_da_url(valore, riferimento)
        if tipo is TipoIndicatore.URL
        else None
    )
    if host is not None:
        osservazione.id_host_derivato = host.id

    if not nome_famiglia:
        return indicatore, osservazione, None, host

    famiglia = MalwareFamily(
        id=calcola_slug(nome_famiglia),
        nome=nome_famiglia,
        origini=["operativa"],
        alias=alias,
        provenienze_alias={voce: [riferimento] for voce in alias},
        provenienze=[riferimento],
    )
    return indicatore, osservazione, famiglia, host


# La fonte distribuisce l'archivio completo come dizionario che associa a ogni
# identificativo il record corrispondente.
def normalizza_file(percorso: Path, id_snapshot: str) -> RisultatoNormalizzazione:
    """Normalizza un intero snapshot di ThreatFox."""
    # Lo stesso indirizzo segnalato da più record produce un solo indicatore e
    # più osservazioni. Ogni osservazione conserva il proprio record di origine,
    # quindi la tracciabilità resta completa.
    with open(percorso, encoding="utf-8") as file_grezzo:
        contenuto = json.load(file_grezzo)

    if not isinstance(next(iter(contenuto.values()), None), list):
        raise SnapshotNonValido(
            f"{percorso}: non ha la forma dell'archivio di ThreatFox"
        )

    indicatori: dict[str, Indicator] = {}
    osservazioni: list[Observation] = []
    famiglie: dict[str, MalwareFamily] = {}
    letti = 0
    scartati = 0

    for identificativo, voce in contenuto.items():
        # A ogni identificativo la fonte associa un elenco, che però contiene
        # sempre un record solo. Se un domani ne contenesse due, l'identificativo
        # non basterebbe a distinguerli: meglio fermarsi che perderne uno per
        # strada in silenzio.
        if len(voce) != 1:
            raise SnapshotNonValido(
                f"{percorso}: l'identificativo {identificativo} porta "
                f"{len(voce)} record, ne serve uno"
            )

        letti += 1
        tradotto = normalizza_record(voce[0], identificativo, id_snapshot)
        if tradotto is None:
            scartati += 1  # tipo non rappresentato o valore non valido
            continue

        indicatore, osservazione, famiglia, host = tradotto
        for trovato in (indicatore, host):
            if trovato is None:
                continue
            gia_visto = indicatori.get(trovato.id)
            if gia_visto is None:
                indicatori[trovato.id] = trovato
            else:
                unisci_entita(gia_visto, trovato)
        osservazioni.append(osservazione)
        if famiglia is not None:
            # Sugli indicatori tenere il primo non perde nulla, perché il loro
            # identificatore è calcolato dal contenuto. Sulle famiglie no: lo
            # stesso nome può arrivare con alias diversi da record diversi —
            # «Mirai» compare con l'alias «Katana» e senza — e gli alias si
            # sommano invece di sostituirsi.
            gia_vista = famiglie.get(famiglia.id)
            if gia_vista is None:
                famiglie[famiglia.id] = famiglia
            else:
                unisci_entita(gia_vista, famiglia)

    return RisultatoNormalizzazione(
        record_letti=letti,
        record_scartati=scartati,
        indicatori=list(indicatori.values()),
        osservazioni=osservazioni,
        famiglie=list(famiglie.values()),
    )
