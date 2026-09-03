"""Entità del modello canonico, ispirato a un sottoinsieme di STIX 2.1."""

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field, model_validator
from normalizzazione.vocabolari import TipoIndicatore, uniforma_valore


# Senza questo collegamento non si potrebbe verificare se un'affermazione del
# sistema poggi su una fonte reale.
class RiferimentoGrezzo(BaseModel):
    """Da quale record grezzo deriva l'entità: la relazione DERIVED_FROM."""

    model_config = ConfigDict(frozen=True)

    id_snapshot: str
    percorso_record: str
    identificativo_naturale: str | None = None


class SourceSnapshot(BaseModel):
    """Un file grezzo acquisito dalla raccolta, come descritto dal manifest."""

    id: str
    fonte: str
    url: str
    acquisito_il: datetime
    nome_file: str
    sha256: str
    dimensione_byte: int


class EntitaConProvenienza(BaseModel):
    """Entità che conserva tutti i record grezzi da cui è stata ricavata."""

    provenienze: list[RiferimentoGrezzo] = Field(min_length=1)


class EntitaConAlias(EntitaConProvenienza):
    """Entità i cui alias restano legati ai record che li dichiarano."""

    alias: list[str] = Field(default_factory=list)
    provenienze_alias: dict[str, list[RiferimentoGrezzo]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def verifica_provenienze_alias(self):
        alias = set(self.alias)
        dichiarati = set(self.provenienze_alias)
        if alias != dichiarati:
            raise ValueError("alias e provenienze_alias devono avere le stesse chiavi")
        if any(not provenienze for provenienze in self.provenienze_alias.values()):
            raise ValueError("ogni alias deve avere almeno una provenienza")
        return self


class Indicator(EntitaConProvenienza):
    """Un indicatore tecnico: indirizzo, dominio, URL o impronta di file."""

    id: str
    tipo: TipoIndicatore
    valore: str


# Più osservazioni possono riferirsi allo stesso indicatore: è questo rapporto
# a rendere misurabile la sovrapposizione fra le fonti.
class Observation(EntitaConProvenienza):
    """Una fonte ha segnalato un indicatore in un dato momento."""

    id: str
    id_indicator: str
    fonte: str
    tipo_minaccia: str | None = None
    porta: int | None = Field(default=None, ge=1, le=65535)
    famiglia_dichiarata: str | None = None
    livello_confidenza: int | None = None
    prima_osservazione: datetime | None = None
    ultima_osservazione: datetime | None = None
    segnalatore: str | None = None
    etichette: list[str] = Field(default_factory=list)
    compromesso: bool | None = (
        None  # host di terzi violato, non infrastruttura dell'attaccante
    )
    indicatore_attivo: bool | None = None
    scade_il: datetime | None = None
    riferimenti: list[str] = Field(default_factory=list)
    id_host_derivato: str | None = None


# I campi sono quelli che la fonte distribuisce davvero. L'archivio completo è
# più scarno dell'interrogazione a cui la raccolta ricorreva prima; attributi che
# nessuna acquisizione popola lascerebbero soltanto proprietà vuote nel grafo.
class MalwareSample(EntitaConProvenienza):
    """Un campione di codice malevolo, identificato dalla sua impronta SHA-256."""

    id: str
    sha256: str
    sha1: str | None = None
    md5: str | None = None
    # Impronte approssimate: due file simili producono valori simili, mentre le
    # impronte crittografiche cambiano del tutto. Servono a riconoscere varianti
    # dello stesso codice, non copie identiche.
    ssdeep: str | None = None
    tlsh: str | None = None
    imphash: str | None = None
    nome_file: str | None = None
    tipo_file: str | None = None
    tipo_mime: str | None = None
    famiglia_dichiarata: str | None = None
    prima_osservazione: datetime | None = None
    segnalatore: str | None = None


# Le basi di conoscenza di riferimento — ATT&CK e Malpedia — assegnano
# identificativi stabili e alias; le fonti di osservazione citano invece le
# famiglie per nome libero. Il campo origine distingue i tre casi, e il livello di
# correlazione potrà ricondurre le une alle altre.
class MalwareFamily(EntitaConAlias):
    """Una famiglia di codice malevolo."""

    id: str
    nome: str
    origini: list[Literal["mitre-attack", "malpedia", "operativa"]]
    tipo_mitre: Literal["malware", "tool"] | None = None
    piattaforme: list[str] = Field(default_factory=list)
    descrizione: str | None = None
    # I gruppi a cui la fonte attribuisce la famiglia, per nome. Sono nomi e non
    # identificatori: ricondurli ai gruppi già censiti spetta alla correlazione,
    # che è l'unico livello autorizzato a stabilire che due nomi designino lo
    # stesso soggetto. Solo Malpedia dichiara questo dato.
    attribuita_a: list[str] = Field(default_factory=list)


# ATT&CK assegna ai gruppi censiti un identificativo stabile; le fonti di
# osservazione li nominano liberamente, come accade per le famiglie. Malpedia sta
# in mezzo: non li censisce, ma li nomina attribuendo loro le famiglie, e due
# gruppi su tre fra quelli che cita non compaiono altrove nel corpus.
class ThreatActor(EntitaConAlias):
    """Un gruppo di attacco."""

    id: str
    nome: str
    origini: list[Literal["mitre-attack", "malpedia", "operativa"]]
    descrizione: str | None = None


class AttackTechnique(EntitaConProvenienza):
    """Una tecnica o sotto-tecnica della tassonomia ATT&CK."""

    id: str
    nome: str
    descrizione: str | None = None
    e_sottotecnica: bool = False
    tattiche: list[str] = Field(default_factory=list)
    piattaforme: list[str] = Field(default_factory=list)


class ThreatReport(EntitaConProvenienza):
    """Un bollettino che raccoglie affermazioni contestuali su una minaccia."""

    id: str
    fonte: str
    titolo: str
    descrizione: str | None = None
    autore: str | None = None
    creato_il: datetime | None = None
    modificato_il: datetime | None = None
    riservatezza: str | None = None
    etichette: list[str] = Field(default_factory=list)
    riferimenti: list[str] = Field(default_factory=list)
    paesi_bersaglio: list[str] = Field(default_factory=list)
    settori_bersaglio: list[str] = Field(default_factory=list)
    indicatori_citati: list[str] = Field(default_factory=list)
    famiglie_citate: list[str] = Field(default_factory=list)
    attori_citati: list[str] = Field(default_factory=list)
    tecniche_citate: list[str] = Field(default_factory=list)


class RisultatoNormalizzazione(BaseModel):
    """Entità prodotte dalla normalizzazione di un file grezzo."""

    record_letti: int = 0
    record_scartati: int = 0
    indicatori: list[Indicator] = Field(default_factory=list)
    osservazioni: list[Observation] = Field(default_factory=list)
    campioni: list[MalwareSample] = Field(default_factory=list)
    famiglie: list[MalwareFamily] = Field(default_factory=list)
    attori: list[ThreatActor] = Field(default_factory=list)
    tecniche: list[AttackTechnique] = Field(default_factory=list)
    report: list[ThreatReport] = Field(default_factory=list)


def calcola_id_indicator(tipo: TipoIndicatore, valore: str) -> str:
    """Identificatore che dipende dal solo contenuto, non dalla fonte."""
    # Due fonti che osservano la stessa cosa ottengono così lo stesso valore, e
    # la corrispondenza emerge senza confrontare tutte le coppie.
    testo = f"{tipo.value}|{valore}"
    return hashlib.sha256(testo.encode("utf-8")).hexdigest()  # impronta in esadecimale


def calcola_id_observation(riferimento: RiferimentoGrezzo) -> str:
    """Identificatore leggibile, che indica da dove viene l'osservazione."""
    return f"{riferimento.id_snapshot}:{riferimento.percorso_record}"


def indicatore_host_da_url(
    url: str, riferimento: RiferimentoGrezzo
) -> Indicator | None:
    """Ricava l'host sintattico di un URL come indicatore tracciabile."""
    host = urlsplit(url).hostname
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        tipo = TipoIndicatore.INDIRIZZO_IP
    except ValueError:
        tipo = TipoIndicatore.DOMINIO
    valore = uniforma_valore(tipo, host)
    riferimento_host = riferimento.model_copy(
        update={"percorso_record": f"{riferimento.percorso_record}.host"}
    )
    return Indicator(
        id=calcola_id_indicator(tipo, valore),
        tipo=tipo,
        valore=valore,
        provenienze=[riferimento_host],
    )


# ThreatFox e MalwareBazaar scrivono l'istante nella stessa forma e nessuna delle
# due dichiara il fuso: si assume UTC, come indicano le rispettive documentazioni.
# È un'assunzione nostra, da riportare fra i limiti, e vale la pena che stia
# scritta in un posto solo. Una data in un formato diverso solleva un errore
# invece di essere interpretata a caso.
def converti_data_utc(testo: str | None) -> datetime | None:
    """Converte una data priva di fuso in datetime con il fuso esplicito."""
    if not testo:
        return None
    momento = datetime.strptime(testo, "%Y-%m-%d %H:%M:%S")  # es. 2026-08-19 15:54:38
    return momento.replace(tzinfo=timezone.utc)  # da data "senza fuso" a data UTC


# Serve dove due voci con lo stesso identificatore portano alias diversi: le
# famiglie e gli attori di origine operativa, il cui identificatore è lo slug del
# nome e non un'impronta del contenuto. Tenere solo la prima voce perderebbe in
# silenzio gli alias dell'altra, e con essi le corrispondenze che quegli alias
# permettono di riconoscere.
def unisci_elenchi(primo: list, secondo: list) -> list:
    """Riunisce due elenchi conservando l'ordine di arrivo, senza ripetizioni."""
    uniti = list(primo)
    presenti = set(primo)
    for voce in secondo:
        if voce not in presenti:
            uniti.append(voce)
            presenti.add(voce)
    return uniti


CAMPI_MULTIPLI = (
    "provenienze",
    "origini",
    "alias",
    "piattaforme",
    "attribuita_a",
    "etichette",
    "riferimenti",
    "paesi_bersaglio",
    "settori_bersaglio",
    "indicatori_citati",
    "famiglie_citate",
    "attori_citati",
    "tecniche_citate",
)


def unisci_entita(esistente: BaseModel, nuova: BaseModel) -> None:
    """Accumula i campi multipli di due rappresentazioni della stessa entità."""
    for campo in CAMPI_MULTIPLI:
        if hasattr(esistente, campo):
            valori = getattr(esistente, campo)
            nuovi_valori = getattr(nuova, campo)
            if campo == "provenienze":
                # Le provenienze possono essere centinaia di migliaia per una
                # sola famiglia. Accodarle costa sempre quanto i soli nuovi
                # elementi; la deduplicazione viene fatta una volta al termine.
                valori.extend(nuovi_valori)
            else:
                setattr(esistente, campo, unisci_elenchi(valori, nuovi_valori))

    if hasattr(esistente, "provenienze_alias"):
        for alias, provenienze in nuova.provenienze_alias.items():
            esistente.provenienze_alias.setdefault(alias, []).extend(provenienze)


def deduplica_entita(entita: BaseModel) -> None:
    """Elimina una volta sola le ripetizioni dai campi multipli di un'entità."""
    for campo in CAMPI_MULTIPLI:
        if hasattr(entita, campo):
            setattr(entita, campo, unisci_elenchi([], getattr(entita, campo)))
    if hasattr(entita, "provenienze_alias"):
        for alias, provenienze in entita.provenienze_alias.items():
            entita.provenienze_alias[alias] = unisci_elenchi([], provenienze)


def calcola_slug(nome: str) -> str:
    """Riduce un nome libero a una forma stabile, uguale per "Cobalt Strike" e "cobalt strike"."""
    con_trattini = re.sub(
        r"[^a-z0-9]+", "-", nome.lower()
    )  # spazi e simboli -> trattino
    return con_trattini.strip("-")  # toglie i trattini ai bordi


def estrai_id_software_attack(nome: str) -> str | None:
    """Legge un ID ATT&CK esplicito da ``Nome - S####`` o dal solo ID."""
    trovato = re.search(r"(?:^|\s+-\s+)(S\d{4})\s*$", nome, flags=re.IGNORECASE)
    return trovato.group(1).upper() if trovato else None
