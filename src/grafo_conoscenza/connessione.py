"""Connessione al grafo di conoscenza Neo4j."""

import os
from neo4j import Driver, GraphDatabase

URI_PREDEFINITO = "bolt://localhost:7687"
UTENTE_PREDEFINITO = "neo4j"


class PasswordMancante(Exception):
    """La variabile d'ambiente NEO4J_PASSWORD non è impostata."""


def apri_driver(uri: str = URI_PREDEFINITO) -> Driver:
    """Apre un driver verso il grafo, con le credenziali lette dall'ambiente."""
    password = os.environ.get("NEO4J_PASSWORD")
    if not password:
        raise PasswordMancante("impostare NEO4J_PASSWORD nell'ambiente (vedi .env)")
    return GraphDatabase.driver(uri, auth=(UTENTE_PREDEFINITO, password))


def verifica_connessione(driver: Driver) -> bool:
    """Controlla che il grafo risponda, eseguendo una query minima."""
    risultato = driver.execute_query("RETURN 1 AS uno")
    return risultato.records[0]["uno"] == 1
