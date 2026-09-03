"""Riconoscimento degli identificatori da cercare per uguaglianza."""

import re
from enum import Enum
from pydantic import BaseModel
from normalizzazione.vocabolari import (
    TipoIndicatore,
    ValoreIndicatoreNonValido,
    uniforma_valore,
)


class TipoIdentificativo(str, Enum):
    """Gli identificatori di ATT&CK, che non sono indicatori tecnici."""

    TECNICA = "tecnica"
    GRUPPO = "gruppo"
    SOFTWARE = "software"


class Riconosciuto(BaseModel):
    """Un valore estratto dalla domanda, con ciò che si presume sia."""

    tipo: TipoIndicatore | TipoIdentificativo
    valore: str


# L'ordine conta: un URL contiene un nome a dominio, e riconoscere prima il
# secondo spezzerebbe il primo. Le impronte si distinguono per lunghezza e i
# limiti di parola impediscono a una SHA-256 di essere letta come una MD5 più
# un residuo.
ESPRESSIONI: tuple[tuple[TipoIndicatore | TipoIdentificativo, re.Pattern], ...] = (
    (
        TipoIndicatore.URL,
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE),
    ),
    (TipoIndicatore.CVE, re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    # Le sotto-tecniche portano il punto: T1055.011 va letta intera, non come
    # T1055 seguita da un numero. Le tre forme sono riconosciute senza badare
    # alle maiuscole, perché chi scrive la domanda non è tenuto a rispettare la
    # convenzione di MITRE, e la forma corretta viene ripristinata dopo.
    (TipoIdentificativo.TECNICA, re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)),
    (TipoIdentificativo.GRUPPO, re.compile(r"\bG\d{4}\b", re.IGNORECASE)),
    (TipoIdentificativo.SOFTWARE, re.compile(r"\bS\d{4}\b", re.IGNORECASE)),
    (TipoIndicatore.HASH_SHA256, re.compile(r"\b[a-fA-F0-9]{64}\b")),
    (TipoIndicatore.HASH_SHA1, re.compile(r"\b[a-fA-F0-9]{40}\b")),
    (TipoIndicatore.HASH_MD5, re.compile(r"\b[a-fA-F0-9]{32}\b")),
    (TipoIndicatore.INDIRIZZO_IP, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    (
        TipoIndicatore.DOMINIO,
        re.compile(
            r"(?<![@\w.-])(?:[\w-]{1,63}\.)+[\w-]{2,63}(?![\w.-])",
            re.IGNORECASE,
        ),
    ),
)


def _indirizzo_valido(valore: str) -> bool:
    """Scarta le quaterne che hanno la forma di un indirizzo ma non lo sono."""
    return all(int(ottetto) <= 255 for ottetto in valore.split("."))


# La punteggiatura della frase può aderire all'URL riconosciuto; va rimossa
# prima della ricerca esatta senza eliminare parentesi appartenenti all'URL.
PUNTEGGIATURA_FINALE = ".,;:!?»\"'"
PARENTESI = {")": "(", "]": "[", "}": "{"}


def _url_ripulito(valore: str) -> str:
    """Toglie dall'URL la punteggiatura con cui finisce la frase che lo contiene.

    La parentesi chiusa si toglie solo se nel valore non ne è stata aperta una:
    dentro un URL può essere legittima, e in una domanda che cita un indirizzo
    fra parentesi è invece il confine della citazione.
    """
    ripulito = valore.rstrip(PUNTEGGIATURA_FINALE)
    while ripulito and ripulito[-1] in PARENTESI:
        chiusa = ripulito[-1]
        aperta = PARENTESI[chiusa]
        if ripulito.count(aperta) >= ripulito.count(chiusa):
            break
        ripulito = ripulito[:-1].rstrip(PUNTEGGIATURA_FINALE)
    return ripulito


def _forma_nel_grafo(tipo: TipoIndicatore | TipoIdentificativo, valore: str) -> str:
    """Applica la stessa forma canonica usata durante la normalizzazione."""
    if isinstance(tipo, TipoIdentificativo):
        return valore.upper()
    if tipo is TipoIndicatore.URL:
        return uniforma_valore(tipo, _url_ripulito(valore))
    return uniforma_valore(tipo, valore)


def riconosci(domanda: str) -> list[Riconosciuto]:
    """Estrae dalla domanda i valori interrogabili per uguaglianza.

    Restituisce i candidati nell'ordine in cui compaiono, senza ripetizioni. Le
    porzioni già attribuite a un tipo non vengono riesaminate dai tipi
    successivi, così l'indirizzo dentro un URL non diventa un secondo candidato.
    """
    consumate: list[tuple[int, int]] = []
    trovati: dict[tuple[str, str], tuple[int, Riconosciuto]] = {}

    def si_sovrappone(inizio: int, fine: int) -> bool:
        return any(inizio < f and i < fine for i, f in consumate)

    for tipo, espressione in ESPRESSIONI:
        for corrispondenza in espressione.finditer(domanda):
            inizio, fine = corrispondenza.span()
            if si_sovrappone(inizio, fine):
                continue
            valore = corrispondenza.group()
            if tipo is TipoIndicatore.INDIRIZZO_IP and not _indirizzo_valido(valore):
                continue
            try:
                normalizzato = _forma_nel_grafo(tipo, valore)
            except ValoreIndicatoreNonValido:
                continue
            consumate.append((inizio, fine))
            trovati.setdefault(
                (str(tipo), normalizzato),
                (inizio, Riconosciuto(tipo=tipo, valore=normalizzato)),
            )

    return [
        elemento for _, (_, elemento) in sorted(trovati.items(), key=lambda v: v[1][0])
    ]
