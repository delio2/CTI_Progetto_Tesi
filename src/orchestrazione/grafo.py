"""Il grafo di esecuzione dell'orchestratore, dalla domanda alla risposta."""

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Send
from neo4j import Driver
from orchestrazione.nodi import (
    crea_recupero,
    fusione,
    instradamento,
    interpretazione,
    sintesi,
    traduzione,
)
from orchestrazione.stato import CompitoRecupero, StatoOrchestrazione


def attiva_specialisti(stato: StatoOrchestrazione) -> list[Send]:
    """Crea un compito di recupero per ciascun dominio selezionato."""
    return [
        Send(
            "recupero",
            CompitoRecupero(
                dominio=dominio,
                domanda_recupero=stato.domanda_recupero,
                riconosciuti=stato.riconosciuti,
            ),
        )
        for dominio in stato.domini
    ]


def costruisci(driver: Driver) -> CompiledStateGraph:
    """Compone il grafo comune alle due configurazioni sperimentali."""
    costruttore = StateGraph(StatoOrchestrazione)

    costruttore.add_node("interpretazione", interpretazione)
    costruttore.add_node("traduzione", traduzione)
    costruttore.add_node("instradamento", instradamento)
    # Il solo nodo con uno schema d'ingresso proprio: riceve un compito per un
    # dominio, non lo stato intero, perché di quello stato ogni esecuzione
    # parallela deve vedere soltanto la propria parte.
    costruttore.add_node(
        "recupero", crea_recupero(driver), input_schema=CompitoRecupero
    )
    costruttore.add_node("fusione", fusione)
    costruttore.add_node("sintesi", sintesi)

    costruttore.add_edge(START, "interpretazione")
    costruttore.add_edge("interpretazione", "traduzione")
    costruttore.add_edge("traduzione", "instradamento")
    costruttore.add_conditional_edges("instradamento", attiva_specialisti, ["recupero"])
    # Arco normale da un nodo aperto a ventaglio: la fusione parte una volta
    # sola, quando tutte le esecuzioni parallele del recupero sono concluse.
    costruttore.add_edge("recupero", "fusione")
    costruttore.add_edge("fusione", "sintesi")
    costruttore.add_edge("sintesi", END)

    return costruttore.compile()
