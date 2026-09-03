"""Lo stato che attraversa il grafo di esecuzione dell'orchestratore."""

import operator
from typing import Annotated, Literal
from pydantic import BaseModel, Field
from recupero.riconoscimento import Riconosciuto

# Le due configurazioni che il Capitolo 5 mette a confronto. Sono valori dello
# stato e non due programmi distinti: il grafo è uno solo, e ciò che cambia è
# la sola decisione presa dal nodo di instradamento. Costruirne due separati
# renderebbe possibile che divergano in qualcosa che nessuno ha dichiarato.
Configurazione = Literal["router", "generale"]


class Evidenza(BaseModel):
    """Un risultato recuperato, con gli archi che lo giustificano."""

    dominio: str
    etichetta: str
    id: str
    contenuto: str
    modo: str
    # Punteggio originale del solo canale: viene mostrato, mai confrontato con
    # quelli prodotti da modalità o etichette diverse.
    punteggio: float
    archi: list[dict] = Field(default_factory=list)


class CompitoRecupero(BaseModel):
    """Ciò che una singola esecuzione del nodo di recupero riceve.

    Il recupero gira una volta per dominio attivato, e ogni esecuzione vede
    soltanto il proprio dominio: è lo schema d'ingresso di quel nodo, non lo
    stato intero del grafo.
    """

    dominio: str
    domanda_recupero: str
    riconosciuti: list[Riconosciuto] = Field(default_factory=list)


class StatoOrchestrazione(BaseModel):
    """Ciò che i nodi si passano, dalla domanda alla risposta."""

    domanda: str
    configurazione: Configurazione = "router"

    # Valorizzati man mano dai nodi.
    domanda_recupero: str | None = None
    riconosciuti: list[Riconosciuto] = Field(default_factory=list)
    domini: list[str] = Field(default_factory=list)

    # Il riduttore non è un dettaglio di stile. Il nodo di recupero viene
    # eseguito una volta per dominio attivato, e le esecuzioni girano in
    # parallelo dentro lo stesso passo: senza operator.add, LangGraph
    # tratterebbe ciascun ritorno come una sostituzione, e delle due uscite
    # sopravvivrebbe soltanto l'ultima. Non un duplicato di troppo: metà dei
    # risultati persi in silenzio.
    recuperate: Annotated[list[Evidenza], operator.add] = Field(default_factory=list)

    # Le evidenze dopo la fusione: unite, private delle ripetizioni e riportate
    # al tetto che vale per entrambe le configurazioni.
    evidenze: list[Evidenza] = Field(default_factory=list)
    risposta: str | None = None
