"""Controlli essenziali sul caricamento e sul grafo Neo4j reale."""

import json
from pathlib import Path

import pytest

from grafo_conoscenza.caricamento import (
    carica_archi,
    carica_nodi,
    proprieta_del_nodo,
    query_archi,
)
from grafo_conoscenza.embedding import DIMENSIONI, genera_embedding_domanda
from grafo_conoscenza.schema import ETICHETTE, applica_schema

PREFISSO = "prova-caricamento:"
SNAPSHOT = {
    "id": PREFISSO + "snapshot",
    "fonte": "Prova",
    "url": "https://esempio.test/api",
    "acquisito_il": "2026-08-19T16:05:31Z",
    "nome_file": "prova.json",
    "sha256": "a" * 64,
    "dimensione_byte": 12,
}
INDICATORE = {
    "id": PREFISSO + "indicatore",
    "tipo": "indirizzo_ip",
    "valore": "203.0.113.1",
    "provenienze": [
        {
            "id_snapshot": SNAPSHOT["id"],
            "percorso_record": "data[7]",
            "identificativo_naturale": "1882389",
        }
    ],
}
ARCO = {
    "tipo_relazione": "DERIVED_FROM",
    "tipo_origine": "Indicator",
    "id_origine": INDICATORE["id"],
    "tipo_destinazione": "SourceSnapshot",
    "id_destinazione": SNAPSHOT["id"],
    "supporti": [SNAPSHOT["id"] + ":data[7]"],
    "regole": ["provenienza registrata alla normalizzazione"],
    "evidenze": [""],
    "percorso_record": "data[7]",
    "identificativo_naturale": "1882389",
}


@pytest.fixture
def grafo_di_prova(driver, tmp_path):
    for nome, righe in [
        ("source_snapshot", [SNAPSHOT]),
        ("indicator", [INDICATORE]),
        ("relazioni", [ARCO]),
    ]:
        (tmp_path / f"{nome}.jsonl").write_text(
            "\n".join(json.dumps(riga) for riga in righe) + "\n", encoding="utf-8"
        )

    def ripulisci():
        for etichetta, identificatore in [
            ("Indicator", INDICATORE["id"]),
            ("SourceSnapshot", SNAPSHOT["id"]),
        ]:
            driver.execute_query(
                f"MATCH (n:{etichetta} {{id: $id}}) DETACH DELETE n",
                id=identificatore,
            )

    ripulisci()
    yield driver, tmp_path
    ripulisci()


def carica_tutto(driver, cartella):
    carica_nodi(driver, cartella / "source_snapshot.jsonl", "SourceSnapshot")
    carica_nodi(driver, cartella / "indicator.jsonl", "Indicator")
    carica_archi(driver, cartella / "relazioni.jsonl")


def test_il_loader_separa_proprieta_dei_nodi_e_provenienza_degli_archi():
    proprieta = proprieta_del_nodo(
        {**INDICATORE, "provenienze_alias": {"alias": INDICATORE["provenienze"]}}
    )
    assert "provenienze" not in proprieta
    assert "provenienze_alias" not in proprieta
    assert proprieta["valore"] == "203.0.113.1"

    provenienza = query_archi("DERIVED_FROM", "Indicator", "SourceSnapshot")
    semantica = query_archi("INDICATES", "Indicator", "MalwareFamily")
    veloce = query_archi("DERIVED_FROM", "Indicator", "SourceSnapshot", crea=True)
    assert "{percorso_record: riga.percorso_record}" in provenienza
    assert "{percorso_record: riga.percorso_record}" not in semantica
    assert "CREATE (a)-[r:DERIVED_FROM" in veloce


def test_schema_e_caricamento_si_possono_ripetere_senza_duplicati(grafo_di_prova):
    driver, cartella = grafo_di_prova
    applica_schema(driver)
    applica_schema(driver)

    vincolate = {
        riga["labelsOrTypes"][0]
        for riga in driver.execute_query("SHOW CONSTRAINTS YIELD labelsOrTypes").records
    }
    assert set(ETICHETTE) <= vincolate

    carica_tutto(driver, cartella)
    carica_tutto(driver, cartella)
    nodo = driver.execute_query(
        "MATCH (n:Indicator {id: $id}) RETURN count(n) AS quanti, properties(n) AS p",
        id=INDICATORE["id"],
    ).records[0]
    arco = driver.execute_query(
        "MATCH (:Indicator {id: $id})-[r:DERIVED_FROM]->() "
        "RETURN count(r) AS quanti, r.percorso_record AS posizione",
        id=INDICATORE["id"],
    ).records[0]
    assert nodo["quanti"] == arco["quanti"] == 1
    assert "provenienze" not in nodo["p"]
    assert arco["posizione"] == "data[7]"


def test_il_grafo_reale_corrisponde_ai_manifest_e_risponde_per_similarita(driver):
    cartella = Path("data/processed")
    percorso_normalizzazione = cartella / "manifest_normalizzazione.json"
    percorso_correlazione = cartella / "manifest_correlazione.json"
    if not percorso_normalizzazione.is_file() or not percorso_correlazione.is_file():
        pytest.skip("dati reali non ancora generati")

    normalizzazione = json.loads(percorso_normalizzazione.read_text(encoding="utf-8"))
    correlazione = json.loads(percorso_correlazione.read_text(encoding="utf-8"))
    file_per_etichetta = {
        "SourceSnapshot": "source_snapshot.jsonl",
        "Indicator": "indicator.jsonl",
        "Observation": "observation.jsonl",
        "MalwareSample": "malware_sample.jsonl",
        "MalwareFamily": "malware_family.jsonl",
        "ThreatActor": "threat_actor.jsonl",
        "AttackTechnique": "attack_technique.jsonl",
        "ThreatReport": "threat_report.jsonl",
    }
    for etichetta, nome_file in file_per_etichetta.items():
        quanti = driver.execute_query(
            f"MATCH (n:{etichetta}) RETURN count(n) AS quanti"
        ).records[0]["quanti"]
        assert quanti == normalizzazione["entita_scritte"][nome_file]

    for tipo, attesi in correlazione["archi_per_tipo"].items():
        quanti = driver.execute_query(
            f"MATCH ()-[r:{tipo}]->() RETURN count(r) AS quanti"
        ).records[0]["quanti"]
        assert quanti == attesi

    annidate = driver.execute_query(
        "MATCH (n) WHERE n.provenienze IS NOT NULL OR n.provenienze_alias IS NOT NULL "
        "RETURN count(n) AS quanti"
    ).records[0]["quanti"]
    dimensioni = driver.execute_query(
        "MATCH (n) WHERE n.embedding IS NOT NULL "
        "RETURN collect(DISTINCT size(n.embedding)) AS dimensioni"
    ).records[0]["dimensioni"]
    indici_non_attivi = driver.execute_query(
        "SHOW INDEXES YIELD state WHERE state <> 'ONLINE' RETURN count(*) AS quanti"
    ).records[0]["quanti"]
    assert annidate == indici_non_attivi == 0
    assert dimensioni == [DIMENSIONI]

    vettore = genera_embedding_domanda("encrypt the victim's files to demand a ransom")
    risultati = driver.execute_query(
        "MATCH (n:AttackTechnique) "
        "SEARCH n IN (VECTOR INDEX indice_vettoriale_attacktechnique "
        "FOR $vettore LIMIT 5) RETURN n.id AS id",
        vettore=vettore,
    ).records
    assert "T1486" in {riga["id"] for riga in risultati}
