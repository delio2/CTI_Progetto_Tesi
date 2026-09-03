"""Normalizzazione degli snapshot di AlienVault OTX."""

import json
from datetime import datetime, timezone
from pathlib import Path
from normalizzazione.io_snapshot import SnapshotNonValido
from normalizzazione.modelli import (
    Indicator,
    MalwareFamily,
    Observation,
    RiferimentoGrezzo,
    RisultatoNormalizzazione,
    ThreatReport,
    ThreatActor,
    calcola_id_indicator,
    calcola_id_observation,
    calcola_slug,
    estrai_id_software_attack,
    indicatore_host_da_url,
    unisci_entita,
)
from normalizzazione.vocabolari import (
    TipoIndicatore,
    ValoreIndicatoreNonValido,
    mappa_tipo_otx,
    uniforma_valore,
)

FONTE = "AlienVault OTX"


def leggi_tlp(pulse: dict) -> str | None:
    """Legge il livello di riservatezza dichiarato dal bollettino."""
    valore = pulse.get("tlp")
    return valore.lower() if valore else None


def converti_data(testo: str | None) -> datetime | None:
    """Converte una data di OTX in datetime con fuso esplicito."""
    # Il formato è ISO ma senza indicazione del fuso: si assume UTC.
    if not testo:
        return None
    momento = datetime.fromisoformat(testo)  # es. 2026-08-19T13:24:07.600000
    if momento.tzinfo is None:
        momento = momento.replace(tzinfo=timezone.utc)
    return momento


# Restituisce None quando la fonte dichiara un tipo che lo schema canonico non
# rappresenta: chi chiama lo conta fra gli scarti anziché interrompersi.
def normalizza_indicatore(
    grezzo: dict, id_snapshot: str, percorso: str
) -> tuple[Indicator, Observation, Indicator | None] | None:
    """Traduce un indicatore contenuto in un pulse, con la sua osservazione."""
    tipo = mappa_tipo_otx(grezzo["type"])
    if tipo is None:
        return None

    riferimento = RiferimentoGrezzo(
        id_snapshot=id_snapshot,
        percorso_record=percorso,
        identificativo_naturale=str(grezzo["id"]),
    )

    try:
        valore = uniforma_valore(tipo, grezzo["indicator"])
    except ValoreIndicatoreNonValido:
        return None

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
        prima_osservazione=converti_data(grezzo.get("created")),
        indicatore_attivo=bool(grezzo.get("is_active")),
        scade_il=converti_data(grezzo.get("expiration")),
        provenienze=[riferimento],
    )
    host = (
        indicatore_host_da_url(valore, riferimento)
        if tipo is TipoIndicatore.URL
        else None
    )
    if host is not None:
        osservazione.id_host_derivato = host.id
    return indicatore, osservazione, host


def normalizza_file(percorso: Path, id_snapshot: str) -> RisultatoNormalizzazione:
    """Normalizza lo snapshot dei pulse OTX sottoscritti."""
    with open(percorso, encoding="utf-8") as file_grezzo:
        contenuto = json.load(file_grezzo)

    if "results" not in contenuto:
        raise SnapshotNonValido(f"{percorso}: manca il campo 'results'")

    indicatori: dict[str, Indicator] = {}
    osservazioni: list[Observation] = []
    famiglie: dict[str, MalwareFamily] = {}
    attori: dict[str, ThreatActor] = {}
    report: list[ThreatReport] = []
    letti = 0
    scartati = 0

    for indice_pulse, pulse in enumerate(contenuto["results"]):
        riferimento_pulse = RiferimentoGrezzo(
            id_snapshot=id_snapshot,
            percorso_record=f"results[{indice_pulse}]",
            identificativo_naturale=str(pulse["id"]),
        )

        id_report = f"otx:{pulse['id']}"
        nomi_famiglie = [
            nome.strip()
            for nome in pulse.get("malware_families") or []
            if nome and nome.strip()
        ]
        for nome_famiglia in nomi_famiglie:
            # Alcuni pulse scrivono già l'identificativo ATT&CK, per esempio
            # "ShadowPad - S0596". Il report conserva il testo completo e la
            # correlazione userà quell'ID; creare anche una famiglia operativa
            # produrrebbe invece un duplicato privo della descrizione MITRE.
            if estrai_id_software_attack(nome_famiglia):
                continue
            famiglia = MalwareFamily(
                id=calcola_slug(nome_famiglia),
                nome=nome_famiglia,
                origini=["operativa"],
                provenienze=[riferimento_pulse],
            )
            gia_vista = famiglie.get(famiglia.id)
            if gia_vista is None:
                famiglie[famiglia.id] = famiglia
            else:
                unisci_entita(gia_vista, famiglia)

        # Il gruppo a cui il pulse attribuisce la campagna. Nessuno di quelli
        # osservati corrisponde a un gruppo censito da ATT&CK: restano entità
        # a sé stanti, che il livello di correlazione potrà ricondurre per nome.
        nome_attore = (pulse.get("adversary") or "").strip()
        if nome_attore:
            attore = ThreatActor(
                id=calcola_slug(nome_attore),
                nome=nome_attore,
                origini=["operativa"],
                provenienze=[riferimento_pulse],
            )
            gia_visto = attori.get(attore.id)
            if gia_visto is None:
                attori[attore.id] = attore
            else:
                unisci_entita(gia_visto, attore)

        indicatori_del_report = []
        for indice, grezzo in enumerate(pulse.get("indicators") or []):
            letti += 1
            tradotto = normalizza_indicatore(
                grezzo,
                id_snapshot,
                f"results[{indice_pulse}].indicators[{indice}]",
            )
            if tradotto is None:
                scartati += 1  # tipo riconosciuto ma fuori dallo schema canonico
                continue
            indicatore, osservazione, host = tradotto
            for trovato in (indicatore, host):
                if trovato is None:
                    continue
                gia_visto = indicatori.get(trovato.id)
                if gia_visto is None:
                    indicatori[trovato.id] = trovato
                else:
                    unisci_entita(gia_visto, trovato)
            osservazioni.append(osservazione)
            if indicatore.id not in indicatori_del_report:
                indicatori_del_report.append(indicatore.id)

        report.append(
            ThreatReport(
                id=id_report,
                fonte=FONTE,
                titolo=(pulse.get("name") or str(pulse["id"])).strip(),
                descrizione=(pulse.get("description") or "").strip() or None,
                autore=(pulse.get("author_name") or "").strip() or None,
                creato_il=converti_data(pulse.get("created")),
                modificato_il=converti_data(pulse.get("modified")),
                riservatezza=leggi_tlp(pulse),
                etichette=list(pulse.get("tags") or []),
                riferimenti=list(pulse.get("references") or []),
                paesi_bersaglio=list(pulse.get("targeted_countries") or []),
                settori_bersaglio=list(pulse.get("industries") or []),
                indicatori_citati=indicatori_del_report,
                famiglie_citate=nomi_famiglie,
                attori_citati=[nome_attore] if nome_attore else [],
                tecniche_citate=list(pulse.get("attack_ids") or []),
                provenienze=[riferimento_pulse],
            )
        )

    return RisultatoNormalizzazione(
        record_letti=letti,
        record_scartati=scartati,
        indicatori=list(indicatori.values()),
        osservazioni=osservazioni,
        famiglie=list(famiglie.values()),
        attori=list(attori.values()),
        report=report,
    )
