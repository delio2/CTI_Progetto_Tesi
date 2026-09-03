"""Caricamento a lotti delle entità e delle relazioni nel grafo di conoscenza."""

import json
from collections import Counter
from pathlib import Path
from neo4j import Driver

DIMENSIONE_LOTTO = 500

# Quanti elementi togliere per transazione: cancellarli tutti insieme supera il
# limite di memoria che Neo4j concede a una singola transazione, 1,3 GB.
ELEMENTI_PER_CANCELLAZIONE = 50_000

# Neo4j ammette come proprietà di un nodo solo valori primitivi o loro elenchi,
# non oggetti annidati. Le provenienze generali passano negli archi DERIVED_FROM;
# quelle degli alias servono durante la correlazione e non sono proprietà del nodo.
CAMPI_ANNIDATI = frozenset({"provenienze", "provenienze_alias"})


def leggi_a_lotti(percorso: Path, dimensione: int = DIMENSIONE_LOTTO):
    """Legge un file JSON Lines e restituisce le righe raggruppate in lotti."""
    lotto = []
    with open(percorso, encoding="utf-8") as file_entita:
        for riga in file_entita:
            lotto.append(json.loads(riga))
            if len(lotto) == dimensione:
                yield lotto
                lotto = []
    if lotto:
        yield lotto


def cancella_a_lotti(driver: Driver, query: str) -> int:
    """Ripete una cancellazione a lotti finché non resta nulla da togliere."""
    totale = 0
    while True:
        quanti = driver.execute_query(query).records[0]["quanti"]
        if not quanti:
            return totale
        totale += quanti


def svuota_grafo(driver: Driver) -> int:
    """Toglie dal grafo tutti i nodi con i loro archi, e restituisce quanti ne ha tolti."""
    # Il caricamento è idempotente sui nodi che ritrova, ma non sa nulla di
    # quelli che l'acquisizione precedente aveva creato e questa non contiene
    # più: senza svuotare, un'entità sparita dalla fonte resterebbe nel grafo per
    # sempre, e con lei le proprietà che il modello non prevede più. Il grafo
    # descrive una sola acquisizione, e si ricostruisce in pochi minuti dai file
    # già normalizzati.
    #
    # Prima gli archi e poi i nodi: DETACH DELETE su un nodo molto collegato —
    # uno SourceSnapshot ne regge oltre un milione — supererebbe da solo il
    # limite di memoria della transazione, per quanto piccolo sia il lotto.
    cancella_a_lotti(
        driver,
        f"MATCH ()-[r]->() WITH r LIMIT {ELEMENTI_PER_CANCELLAZIONE} "
        "DELETE r RETURN count(*) AS quanti",
    )
    return cancella_a_lotti(
        driver,
        f"MATCH (n) WITH n LIMIT {ELEMENTI_PER_CANCELLAZIONE} "
        "DELETE n RETURN count(*) AS quanti",
    )


def proprieta_del_nodo(riga: dict) -> dict:
    """Le proprietà primitive da scrivere sul nodo."""
    return {
        chiave: valore
        for chiave, valore in riga.items()
        if chiave not in CAMPI_ANNIDATI
    }


def carica_nodi(driver: Driver, percorso: Path, etichetta: str) -> int:
    """Carica un file di entità come nodi di una singola etichetta."""
    # L'etichetta non è parametrizzabile in Cypher: va scritta nella query.
    # È comunque un valore fisso, non un dato esterno, quindi non c'è rischio
    # di iniezione.
    query = f"UNWIND $lotto AS riga MERGE (n:{etichetta} {{id: riga.id}}) SET n += riga"
    totale = 0
    for lotto in leggi_a_lotti(percorso):
        driver.execute_query(query, lotto=[proprieta_del_nodo(riga) for riga in lotto])
        totale += len(lotto)
    return totale


def query_archi(
    tipo_relazione: str,
    tipo_origine: str,
    tipo_destinazione: str,
    crea: bool = False,
) -> str:
    """La query che crea gli archi di una sola tripla."""
    # Le etichette e il tipo di relazione vanno scritti nella query e non passati
    # come parametri, che Cypher non ammette in quelle posizioni: di qui la
    # necessità di raggruppare per tripla invece di caricare tutto insieme.
    proprieta_identificative = (
        " {percorso_record: riga.percorso_record}"
        if tipo_relazione == "DERIVED_FROM"
        else ""
    )
    operazione = "CREATE" if crea else "MERGE"
    return (
        f"UNWIND $lotto AS riga "
        f"MATCH (a:{tipo_origine} {{id: riga.id_origine}}) "
        f"MATCH (b:{tipo_destinazione} {{id: riga.id_destinazione}}) "
        f"{operazione} (a)-[r:{tipo_relazione}{proprieta_identificative}]->(b) "
        f"SET r.supporti = riga.supporti, r.regole = riga.regole, "
        f"r.evidenze = riga.evidenze, "
        f"r.percorso_record = riga.percorso_record, "
        f"r.identificativo_naturale = riga.identificativo_naturale "
        # Gli archi davvero scritti, non le righe lette: se un capo mancasse, il
        # MATCH non troverebbe il nodo e la riga passerebbe senza creare nulla.
        # Contare le righe darebbe un resoconto più alto del grafo reale, ed è un
        # numero che l'elaborato cita.
        f"RETURN count(r) AS creati"
    )


def carica_archi(driver: Driver, percorso: Path, crea: bool = False) -> dict[str, int]:
    """Carica le relazioni, raggruppate per tripla (tipo, origine, destinazione).

    ``crea`` evita le ricerche di duplicati quando il chiamante ha appena
    svuotato il grafo e il file verificato è già deduplicato.
    """
    # Il file delle relazioni supera il gigabyte: si legge una riga per volta e
    # ogni tripla parte appena ha un lotto pieno, così la memoria occupata
    # dipende dal numero delle triple, che è una ventina, e non da quello
    # degli archi. Raccoglierli tutti prima di cominciare costerebbe alcuni
    # gigabyte di memoria per non guadagnare nulla.
    lotti = {}
    conteggi = Counter()

    def scrivi(tripla: tuple, lotto: list) -> int:
        """Scrive un lotto di archi e restituisce quanti ne ha davvero creati."""
        esito = driver.execute_query(query_archi(*tripla, crea=crea), lotto=lotto)
        return esito.records[0]["creati"]

    with open(percorso, encoding="utf-8") as file_relazioni:
        for riga in file_relazioni:
            arco = json.loads(riga)
            tripla = (
                arco["tipo_relazione"],
                arco["tipo_origine"],
                arco["tipo_destinazione"],
            )
            lotto = lotti.setdefault(tripla, [])
            lotto.append(arco)
            if len(lotto) == DIMENSIONE_LOTTO:
                conteggi[tripla] += scrivi(tripla, lotto)
                lotti[tripla] = []

    for tripla, lotto in lotti.items():
        if lotto:  # la coda, più corta di un lotto pieno
            conteggi[tripla] += scrivi(tripla, lotto)

    return {
        f"{tipo_relazione} {tipo_origine}->{tipo_destinazione}": quanti
        for (
            tipo_relazione,
            tipo_origine,
            tipo_destinazione,
        ), quanti in conteggi.items()
    }
