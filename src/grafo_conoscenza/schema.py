"""Vincoli e indici del grafo di conoscenza."""

from neo4j import Driver

# Un vincolo di unicità per etichetta: rende idempotente il caricamento, perché
# MERGE su un id già presente aggiorna il nodo invece di duplicarlo.
ETICHETTE = (
    "SourceSnapshot",
    "Indicator",
    "Observation",
    "MalwareSample",
    "MalwareFamily",
    "ThreatActor",
    "AttackTechnique",
    "ThreatReport",
)

INDICI_SUPERATI = ("indice_nomi_entita", "indice_vettoriale_textchunk")
VINCOLI_SUPERATI = ("unico_id_domain", "unico_id_textchunk")


def rimuovi_schema_superato(driver: Driver) -> None:
    """Elimina gli oggetti rimasti dal modello precedente."""
    for nome in INDICI_SUPERATI:
        driver.execute_query(f"DROP INDEX {nome} IF EXISTS")
    for nome in VINCOLI_SUPERATI:
        driver.execute_query(f"DROP CONSTRAINT {nome} IF EXISTS")


def crea_vincoli(driver: Driver) -> None:
    """Un vincolo di unicità sull'id di ciascuna etichetta."""
    for etichetta in ETICHETTE:
        nome_vincolo = f"unico_id_{etichetta.lower()}"
        driver.execute_query(
            f"CREATE CONSTRAINT {nome_vincolo} IF NOT EXISTS "
            f"FOR (n:{etichetta}) REQUIRE n.id IS UNIQUE"
        )


def crea_indici_esatti(driver: Driver) -> None:
    """Indici per la ricerca esatta: indicatori e impronte dei campioni."""
    # Composito su (tipo, valore): copre hash, IP, domini, URL e CVE in un
    # colpo solo, perché sono tutti valori dello stesso campo di Indicator.
    driver.execute_query(
        "CREATE INDEX indice_indicator_tipo_valore IF NOT EXISTS "
        "FOR (n:Indicator) ON (n.tipo, n.valore)"
    )
    # Il campo sha256 di MalwareSample è già coperto dal vincolo di unicità,
    # essendo anche il suo id: qui servono solo gli altri due.
    driver.execute_query(
        "CREATE INDEX indice_sample_md5 IF NOT EXISTS FOR (n:MalwareSample) ON (n.md5)"
    )
    driver.execute_query(
        "CREATE INDEX indice_sample_sha1 IF NOT EXISTS "
        "FOR (n:MalwareSample) ON (n.sha1)"
    )


# Un indice per etichetta permette di applicare il limite direttamente dentro
# Neo4j, senza materializzare tutti i risultati e filtrarli dopo.
INDICI_TESTUALI = {
    "MalwareFamily": "indice_testuale_malwarefamily",
    "ThreatActor": "indice_testuale_threatactor",
    "AttackTechnique": "indice_testuale_attacktechnique",
}


def crea_indici_fulltext(driver: Driver) -> None:
    """Crea un indice full-text su nome e alias per ogni etichetta."""
    # Deliberatamente non sulle descrizioni: quelle sono riservate alla ricerca
    # per similarità, che userà l'indice vettoriale di una fase successiva.
    for etichetta, nome_indice in INDICI_TESTUALI.items():
        driver.execute_query(
            f"CREATE FULLTEXT INDEX {nome_indice} IF NOT EXISTS "
            f"FOR (n:{etichetta}) ON EACH [n.nome, n.alias]"
        )


# Le etichette i cui contenuti descrittivi entrano nella ricerca per similarità.
# Gli indicatori ne restano fuori per scelta dichiarata nel testo approvato: un
# indirizzo o un'impronta non hanno un significato che un vettore possa
# avvicinare a quello di un altro, e cercarli per somiglianza sarebbe fuorviante.
ETICHETTE_VETTORIALI = (
    "MalwareFamily",
    "ThreatActor",
    "AttackTechnique",
    "ThreatReport",
)


def crea_indici_vettoriali(driver: Driver, dimensioni: int) -> None:
    """Un indice vettoriale per etichetta, sulla proprietà embedding."""
    # Le dimensioni le decide il modello scelto, quindi arrivano dal chiamante:
    # questo modulo non deve importare la libreria di calcolo per conoscerle.
    for etichetta in ETICHETTE_VETTORIALI:
        nome = f"indice_vettoriale_{etichetta.lower()}"
        # Un indice vettoriale nasce con un numero fisso di dimensioni e non lo
        # cambia: se si sostituisce il modello, "IF NOT EXISTS" lascerebbe in
        # piedi quello vecchio e i nuovi vettori verrebbero rifiutati. Va quindi
        # eliminato prima, altrimenti il difetto resterebbe silenzioso.
        esistente = driver.execute_query(
            "SHOW INDEXES YIELD name, options WHERE name = $nome "
            "RETURN options['indexConfig']['vector.dimensions'] AS dimensioni",
            nome=nome,
        ).records
        if esistente and esistente[0]["dimensioni"] != dimensioni:
            driver.execute_query(f"DROP INDEX {nome}")

        driver.execute_query(
            f"CREATE VECTOR INDEX {nome} IF NOT EXISTS "
            f"FOR (n:{etichetta}) ON (n.embedding) "
            "OPTIONS {indexConfig: {`vector.dimensions`: $dimensioni, "
            "`vector.similarity_function`: 'cosine'}}",
            dimensioni=dimensioni,
        )


def applica_schema(driver: Driver) -> None:
    """Crea vincoli e indici, in un'unica chiamata idempotente."""
    rimuovi_schema_superato(driver)
    crea_vincoli(driver)
    crea_indici_esatti(driver)
    crea_indici_fulltext(driver)
