"""Vocabolario canonico degli indicatori e mappature dalle singole fonti."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit
from enum import Enum


class TipoIndicatore(str, Enum):
    """Tipi di indicatore previsti dallo schema canonico."""

    INDIRIZZO_IP = "indirizzo_ip"
    DOMINIO = "dominio"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    CVE = "cve"


class TipoIndicatoreNonMappato(Exception):
    """La fonte espone un tipo di indicatore che lo schema canonico non prevede."""


class ValoreIndicatoreNonValido(ValueError):
    """Il valore dichiarato non ha la forma richiesta dal proprio tipo."""


MAPPA_THREATFOX = {
    "ip:port": TipoIndicatore.INDIRIZZO_IP,  # il parser separa indirizzo e porta
    "domain": TipoIndicatore.DOMINIO,
    "url": TipoIndicatore.URL,
    "md5_hash": TipoIndicatore.HASH_MD5,
    "sha1_hash": TipoIndicatore.HASH_SHA1,
    "sha256_hash": TipoIndicatore.HASH_SHA256,
}

MAPPA_OTX = {
    "IPv4": TipoIndicatore.INDIRIZZO_IP,
    "domain": TipoIndicatore.DOMINIO,
    "hostname": TipoIndicatore.DOMINIO,  # le altre fonti non fanno questa distinzione
    "URL": TipoIndicatore.URL,
    "FileHash-MD5": TipoIndicatore.HASH_MD5,
    "FileHash-SHA1": TipoIndicatore.HASH_SHA1,
    "FileHash-SHA256": TipoIndicatore.HASH_SHA256,
    "CVE": TipoIndicatore.CVE,
}

# Tipi che le fonti espongono e che lo schema canonico non rappresenta. Una
# regola YARA è un criterio di rilevamento, non un indicatore; un intervallo
# CIDR designa un insieme di indirizzi e non uno solo; un indirizzo di posta e
# un portafoglio Bitcoin appartengono a categorie che il modello approvato non
# prevede. Elencarli qui, invece di lasciarli cadere nel caso generale, fa sì
# che vengano contati fra gli scarti mentre un tipo davvero inatteso continua a
# interrompere l'elaborazione.
TIPI_NON_RAPPRESENTATI = frozenset({"email", "YARA", "CIDR", "BitcoinAddress"})


def _traduci(mappa: dict, fonte: str, tipo_grezzo: str) -> TipoIndicatore | None:
    """Cerca il tipo nella mappa della fonte, rifiutando quelli non previsti."""
    if tipo_grezzo in TIPI_NON_RAPPRESENTATI:
        return None  # riconosciuto, ma fuori dallo schema: chi chiama lo conta
    if tipo_grezzo not in mappa:
        raise TipoIndicatoreNonMappato(f"{fonte}: tipo '{tipo_grezzo}' non previsto")
    return mappa[tipo_grezzo]


def mappa_tipo_threatfox(tipo_grezzo: str) -> TipoIndicatore | None:
    """Traduce il campo ioc_type di ThreatFox nel tipo canonico."""
    return _traduci(MAPPA_THREATFOX, "ThreatFox", tipo_grezzo)


def mappa_tipo_otx(tipo_grezzo: str) -> TipoIndicatore | None:
    """Traduce il campo type di un indicatore OTX nel tipo canonico."""
    return _traduci(MAPPA_OTX, "AlienVault OTX", tipo_grezzo)


SCHEMI_DEFANG = {"hxxp": "http", "hxxps": "https"}
PORTE_STANDARD = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ws": 80,
    "wss": 443,
    "tftp": 69,
}
LUNGHEZZA_HASH = {
    TipoIndicatore.HASH_MD5: 32,
    TipoIndicatore.HASH_SHA1: 40,
    TipoIndicatore.HASH_SHA256: 64,
}


def _uniforma_dominio(valore: str) -> str:
    """Converte un nome DNS nella forma ASCII usata per confrontarlo."""
    dominio = valore.strip().lower().removesuffix(".")
    if not dominio:
        raise ValoreIndicatoreNonValido(f"dominio non valido: {valore!r}")

    try:
        forma_dns = dominio.encode("idna")
    except UnicodeError as errore:
        raise ValoreIndicatoreNonValido(f"dominio non valido: {valore!r}") from errore
    etichette = forma_dns.split(b".")
    if len(forma_dns) > 253 or any(
        not re.fullmatch(rb"[a-z0-9_-]{1,63}", etichetta)
        or etichetta.startswith(b"-")
        or etichetta.endswith(b"-")
        for etichetta in etichette
    ):
        raise ValoreIndicatoreNonValido(f"dominio non valido: {valore!r}")
    return forma_dns.decode("ascii")


def _uniforma_url(valore: str) -> str:
    """Uniforma solo le parti di un URL che non distinguono la risorsa."""
    originale = valore.strip()
    parti = urlsplit(originale)
    schema = SCHEMI_DEFANG.get(parti.scheme.lower(), parti.scheme.lower())
    if not schema or not parti.hostname:
        raise ValoreIndicatoreNonValido(f"URL non valido: {valore!r}")

    try:
        porta = parti.port
    except ValueError as errore:
        raise ValoreIndicatoreNonValido(f"URL non valido: {valore!r}") from errore

    host = parti.hostname
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = _uniforma_dominio(host)
    if ":" in host:
        host = f"[{host}]"

    credenziali = ""
    if "@" in parti.netloc:
        credenziali = parti.netloc.rsplit("@", 1)[0] + "@"
    porta_testo = (
        "" if porta is None or PORTE_STANDARD.get(schema) == porta else f":{porta}"
    )
    percorso = parti.path or ("/" if schema in {"http", "https"} else "")
    canonico = urlunsplit(
        (
            schema,
            f"{credenziali}{host}{porta_testo}",
            percorso,
            parti.query,
            parti.fragment,
        )
    )

    # urlsplit non distingue un componente vuoto da uno assente. I due
    # delimitatori restano invece parte del valore esatto conservato nel grafo.
    if "?" in originale.partition("#")[0] and not parti.query:
        posizione = canonico.find("#")
        canonico = (
            canonico + "?"
            if posizione < 0
            else canonico[:posizione] + "?" + canonico[posizione:]
        )
    if "#" in originale and not parti.fragment:
        canonico += "#"
    return canonico


def uniforma_valore(tipo: TipoIndicatore, valore: str) -> str:
    """Riconduce il valore alla forma con cui verrà confrontato fra le fonti."""
    if tipo is TipoIndicatore.URL:
        return _uniforma_url(valore)
    if tipo is TipoIndicatore.DOMINIO:
        return _uniforma_dominio(valore)
    if tipo is TipoIndicatore.INDIRIZZO_IP:
        try:
            return str(ipaddress.ip_address(valore.strip()))
        except ValueError as errore:
            raise ValoreIndicatoreNonValido(
                f"indirizzo IP non valido: {valore!r}"
            ) from errore
    if tipo in LUNGHEZZA_HASH:
        impronta = valore.strip().lower()
        if len(impronta) != LUNGHEZZA_HASH[tipo] or not re.fullmatch(
            r"[0-9a-f]+", impronta
        ):
            raise ValoreIndicatoreNonValido(f"impronta non valida: {valore!r}")
        return impronta
    if tipo is TipoIndicatore.CVE:
        cve = valore.strip().lower()
        if not re.fullmatch(r"cve-\d{4}-\d{4,}", cve):
            raise ValoreIndicatoreNonValido(f"CVE non valido: {valore!r}")
        return cve
    raise ValoreIndicatoreNonValido(f"tipo di indicatore non previsto: {tipo!r}")
