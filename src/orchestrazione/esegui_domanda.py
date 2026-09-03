"""Esecuzione dell'orchestratore su una singola domanda."""

import argparse
import time
from langgraph.graph.state import CompiledStateGraph
from grafo_conoscenza.connessione import apri_driver
from orchestrazione.grafo import costruisci
from orchestrazione.registro import registra
from orchestrazione.stato import Configurazione, StatoOrchestrazione

DOMANDA_RISCALDAMENTO = "Che cosa descrive la tecnica T1055?"
CONFIGURAZIONI_CONFRONTO: tuple[Configurazione, ...] = ("router", "generale")


def rispondi(
    grafo: CompiledStateGraph,
    domanda: str,
    configurazione: Configurazione = "router",
    registra_esecuzione: bool = True,
    ordine_esecuzione: int | None = None,
) -> tuple[StatoOrchestrazione, int]:
    """Esegue un grafo già compilato, misura la durata e registra il percorso."""
    avvio = time.perf_counter()
    esito = grafo.invoke(
        StatoOrchestrazione(domanda=domanda, configurazione=configurazione)
    )
    # La latenza si misura attorno alla sola esecuzione del grafo: la
    # costruzione e l'apertura della connessione restano fuori, perché in
    # esercizio avvengono una volta sola e non a ogni domanda.
    millisecondi = round((time.perf_counter() - avvio) * 1000)

    stato = StatoOrchestrazione.model_validate(esito)
    if registra_esecuzione:
        registra(stato, millisecondi, ordine_esecuzione=ordine_esecuzione)
    return stato, millisecondi


def riscalda(grafo: CompiledStateGraph) -> None:
    """Carica modelli, indici e cache senza contaminare il registro."""
    rispondi(
        grafo,
        DOMANDA_RISCALDAMENTO,
        "generale",
        registra_esecuzione=False,
    )


def ordine_confronto(numero: int) -> tuple[Configurazione, ...]:
    """Alterna quale configurazione parte per prima fra domande successive."""
    if numero % 2 == 0:
        return CONFIGURAZIONI_CONFRONTO
    return tuple(reversed(CONFIGURAZIONI_CONFRONTO))


def confronta(grafo: CompiledStateGraph, domanda: str, numero: int) -> dict[str, dict]:
    """Esegue entrambe le configurazioni nell'ordine bilanciato della domanda."""
    esiti = {}
    for posizione, configurazione in enumerate(ordine_confronto(numero), start=1):
        stato, millisecondi = rispondi(
            grafo,
            domanda,
            configurazione,
            ordine_esecuzione=posizione,
        )
        esiti[configurazione] = {
            "stato": stato,
            "millisecondi": millisecondi,
        }
    return esiti


def esegui(
    domanda: str, configurazione: Configurazione = "router"
) -> StatoOrchestrazione:
    """Porta una domanda dall'italiano alla risposta, per una sola esecuzione."""
    driver = apri_driver()
    try:
        grafo = costruisci(driver)
        riscalda(grafo)
        stato, _ = rispondi(grafo, domanda, configurazione)
        return stato
    finally:
        driver.close()


def leggi_argomenti() -> argparse.Namespace:
    """Legge la domanda e la configurazione dalla riga di comando."""
    lettore = argparse.ArgumentParser(description=__doc__)
    lettore.add_argument("domanda", help="la domanda, in italiano")
    lettore.add_argument(
        "--generale",
        action="store_true",
        help="interroga l'intero grafo senza instradamento, "
        "cioè la configurazione di paragone dell'esperimento",
    )
    return lettore.parse_args()


if __name__ == "__main__":
    argomenti = leggi_argomenti()
    stato = esegui(argomenti.domanda, "generale" if argomenti.generale else "router")

    print(f"domanda tradotta : {stato.domanda_recupero}")
    print(f"domini attivati  : {', '.join(stato.domini)}")
    print(
        f"evidenze         : {len(stato.evidenze)} (recuperate {len(stato.recuperate)})"
    )
    print()
    print(stato.risposta)
