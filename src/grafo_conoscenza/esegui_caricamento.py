"""Popolamento del grafo di conoscenza a partire dalle entità normalizzate."""

from pathlib import Path
from grafo_conoscenza.caricamento import carica_archi, carica_nodi, svuota_grafo
from grafo_conoscenza.connessione import apri_driver
from grafo_conoscenza.integrita import NOME_FILE_RELAZIONI, verifica_correlazione
from grafo_conoscenza.schema import applica_schema

CARTELLA_NORMALIZZATI = Path("data/processed")

# Il file da cui caricare ciascuna etichetta.
FILE_PER_ETICHETTA = {
    "SourceSnapshot": "source_snapshot.jsonl",
    "Indicator": "indicator.jsonl",
    "Observation": "observation.jsonl",
    "MalwareSample": "malware_sample.jsonl",
    "MalwareFamily": "malware_family.jsonl",
    "ThreatActor": "threat_actor.jsonl",
    "AttackTechnique": "attack_technique.jsonl",
    "ThreatReport": "threat_report.jsonl",
}


def esegui(cartella_normalizzati: Path = CARTELLA_NORMALIZZATI) -> dict:
    """Svuota il grafo e lo ripopola con lo snapshot corrente."""
    # La verifica precede perfino l'apertura del driver: un file mancante,
    # alterato o correlato con una normalizzazione diversa non deve poter
    # cancellare il grafo valido già presente.
    verifica_correlazione(cartella_normalizzati, tuple(FILE_PER_ETICHETTA.values()))

    # Il grafo rappresenta un'acquisizione sola: ripartire da vuoto è l'unico
    # modo perché rispecchi i file normalizzati e nient'altro.
    driver = apri_driver()
    try:
        tolti = svuota_grafo(driver)
        applica_schema(driver)

        nodi_caricati = {}
        for etichetta, nome_file in FILE_PER_ETICHETTA.items():
            nodi_caricati[etichetta] = carica_nodi(
                driver, cartella_normalizzati / nome_file, etichetta
            )

        archi_caricati = carica_archi(
            driver,
            cartella_normalizzati / NOME_FILE_RELAZIONI,
            crea=True,
        )
        return {"tolti": tolti, "nodi": nodi_caricati, "archi": archi_caricati}
    finally:
        driver.close()


if __name__ == "__main__":
    esito = esegui()
    print(f"nodi rimossi dall'acquisizione precedente: {esito['tolti']}")
    print("nodi:")
    for etichetta, quanti in esito["nodi"].items():
        print(f"  {etichetta:18} {quanti:7}")
    print("archi:")
    for descrizione, quanti in sorted(esito["archi"].items()):
        print(f"  {descrizione:46} {quanti:7}")
