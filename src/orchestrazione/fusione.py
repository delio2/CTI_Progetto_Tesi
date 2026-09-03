"""Fusione delle uscite dei recuperatori attivati per la stessa domanda."""

from orchestrazione.stato import Evidenza
from recupero.specialista import PRECEDENZA_MODI

MASSIMO_EVIDENZE = 30


def tetto_evidenze() -> int:
    """Tetto comune alle due configurazioni prima della sintesi."""
    return MASSIMO_EVIDENZE


def rango(evidenza: Evidenza) -> tuple:
    """Sceglie l'occorrenza migliore dello stesso nodo."""
    return (
        PRECEDENZA_MODI[evidenza.modo],
        -evidenza.punteggio,
        evidenza.etichetta,
        evidenza.id,
        evidenza.dominio,
    )


def fondi(recuperate: list[Evidenza]) -> list[Evidenza]:
    """Deduplica e alterna le etichette senza mescolare i punteggi dei canali."""
    migliori: dict[tuple[str, str], Evidenza] = {}
    for evidenza in recuperate:
        # Gli identificativi sono calcolati per tipo e non sono unici fra tipi
        # diversi: sei nomi ricorrono sia come famiglia sia come gruppo, quindi
        # a individuare un nodo serve la coppia etichetta-identificativo.
        chiave = (evidenza.etichetta, evidenza.id)
        precedente = migliori.get(chiave)
        if precedente is None or rango(evidenza) < rango(precedente):
            migliori[chiave] = evidenza

    ordinate = []
    for modo in PRECEDENZA_MODI:
        canali: dict[str, list[Evidenza]] = {}
        for evidenza in migliori.values():
            if evidenza.modo == modo:
                canali.setdefault(evidenza.etichetta, []).append(evidenza)
        for canale in canali.values():
            canale.sort(key=lambda e: (-e.punteggio, e.etichetta, e.id, e.dominio))
        for posizione in range(max(map(len, canali.values()), default=0)):
            for etichetta in sorted(canali):
                if posizione < len(canali[etichetta]):
                    ordinate.append(canali[etichetta][posizione])
    return ordinate[: tetto_evidenze()]
