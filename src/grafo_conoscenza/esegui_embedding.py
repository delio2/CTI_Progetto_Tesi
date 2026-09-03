"""Calcolo e persistenza delle rappresentazioni vettoriali nel grafo."""

from neo4j import Driver
from grafo_conoscenza.connessione import apri_driver
from grafo_conoscenza.embedding import DIMENSIONI, genera_embedding
from grafo_conoscenza.schema import crea_indici_vettoriali

# Espressioni Cypher statiche: i report restano ricercabili anche quando OTX
# fornisce soltanto il titolo, mentre le altre entità richiedono la descrizione.
TESTO_PER_ETICHETTA = {
    "MalwareFamily": "n.descrizione",
    "ThreatActor": "n.descrizione",
    "AttackTechnique": "n.descrizione",
    "ThreatReport": (
        "CASE WHEN n.descrizione IS NULL OR trim(n.descrizione) = '' "
        "THEN n.titolo ELSE n.titolo + ' — ' + n.descrizione END"
    ),
}

DIMENSIONE_LOTTO = 500


def leggi_testi(
    driver: Driver, etichetta: str, espressione: str
) -> list[tuple[str, str]]:
    """Gli identificatori e i testi dei nodi che hanno qualcosa da vettorializzare."""
    # I nodi privi di testo si saltano invece di far fallire l'esecuzione: un
    # centinaio di famiglie di origine operativa non ha descrizione, perché
    # nessuna delle fonti che le nominano ne fornisce una.
    risultato = driver.execute_query(
        f"MATCH (n:{etichetta}) WITH n, trim({espressione}) AS testo "
        "WHERE testo <> '' RETURN n.id AS id, testo ORDER BY n.id"
    )
    # L'ordinamento per identificatore rende l'esecuzione ripetibile: senza,
    # l'ordine dei nodi restituiti dal grafo non è garantito stabile.
    return [(riga["id"], riga["testo"]) for riga in risultato.records]


def scrivi_embedding(driver: Driver, etichetta: str, righe: list[dict]) -> None:
    """Scrive i vettori sui rispettivi nodi, a lotti."""
    query = (
        f"UNWIND $lotto AS riga MATCH (n:{etichetta} {{id: riga.id}}) "
        f"SET n.embedding = riga.embedding"
    )
    for indice in range(0, len(righe), DIMENSIONE_LOTTO):
        driver.execute_query(query, lotto=righe[indice : indice + DIMENSIONE_LOTTO])


def vettorializza_etichetta(driver: Driver, etichetta: str, espressione: str) -> int:
    """Vettorializza i testi di una sola etichetta e restituisce quanti ne ha trattati."""
    testi = leggi_testi(driver, etichetta, espressione)
    vettori = genera_embedding([testo for _, testo in testi])
    righe = [
        {"id": identificatore, "embedding": vettore}
        for (identificatore, _), vettore in zip(testi, vettori)
    ]
    scrivi_embedding(driver, etichetta, righe)
    return len(righe)


def esegui() -> dict[str, int]:
    """Crea gli indici vettoriali e vi porta i contenuti testuali del grafo."""
    driver = apri_driver()
    try:
        crea_indici_vettoriali(driver, DIMENSIONI)
        return {
            etichetta: vettorializza_etichetta(driver, etichetta, espressione)
            for etichetta, espressione in TESTO_PER_ETICHETTA.items()
        }
    finally:
        driver.close()


if __name__ == "__main__":
    conteggi = esegui()
    for etichetta, quanti in conteggi.items():
        print(f"  {etichetta:18} {quanti:6} vettori")
    print(f"  {'TOTALE':18} {sum(conteggi.values()):6}")
