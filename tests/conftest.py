"""Fixture condivise dalle verifiche automatiche."""

import json
import shutil
from pathlib import Path
import pytest
from neo4j.exceptions import Neo4jError, ServiceUnavailable
from grafo_conoscenza.connessione import (
    PasswordMancante,
    apri_driver,
    verifica_connessione,
)
from normalizzazione.io_snapshot import calcola_impronta


@pytest.fixture
def prepara_snapshot(tmp_path):
    """Ricostruisce uno snapshot di raccolta dalle fixture, manifest compreso.

    Riceve le fonti da includere come coppie (nome della fonte, percorso della
    fixture) e restituisce le due cartelle su cui far girare la pipeline.
    """

    def prepara(fonti: list[tuple[str, Path]]):
        grezzi = tmp_path / "raw"
        grezzi.mkdir(exist_ok=True)

        voci = []
        for fonte, sorgente in fonti:
            shutil.copyfile(sorgente, grezzi / sorgente.name)
            voci.append(
                {
                    "source": fonte,
                    "url": "https://esempio.test/api",
                    "fetchedAt": "2026-08-19T16:05:31.984Z",
                    "fileName": sorgente.name,
                    # L'impronta si calcola sul file appena copiato: è la stessa
                    # verifica che la raccolta esegue sullo snapshot vero.
                    "sha256": calcola_impronta(grezzi / sorgente.name),
                    "sizeBytes": (grezzi / sorgente.name).stat().st_size,
                }
            )

        (grezzi / "manifest.json").write_text(
            json.dumps({"sources": voci}), encoding="utf-8"
        )
        return grezzi, tmp_path / "processed"

    return prepara


@pytest.fixture
def driver():
    """Un driver connesso, o il test viene saltato se Neo4j non è raggiungibile."""
    # Le verifiche di questo gruppo girano contro un grafo vero: saltarle quando
    # il container non è acceso mantiene la suite verde senza rinunciare al
    # controllo quando invece lo è.
    try:
        driver = apri_driver()
        verifica_connessione(driver)
    except (PasswordMancante, ServiceUnavailable, Neo4jError, OSError):
        pytest.skip("Neo4j non raggiungibile: avviare con docker compose up -d neo4j")
    yield driver
    driver.close()
