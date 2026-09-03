"""Recuperatori configurabili per i tre domini e per il grafo completo."""

import re
import threading
from functools import lru_cache
from neo4j import Driver, Record
from neo4j_graphrag.retrievers.base import Retriever
from neo4j_graphrag.types import RawSearchResult, RetrieverResultItem
from pydantic import BaseModel
from grafo_conoscenza.embedding import genera_embedding_domanda
from grafo_conoscenza.schema import INDICI_TESTUALI
from normalizzazione.vocabolari import TipoIndicatore
from recupero.riconoscimento import Riconosciuto, TipoIdentificativo, riconosci

# Limiti comuni alle configurazioni confrontate.
RISULTATI_PER_CANALE = 5
ARCHI_PER_NODO = 3
SUPPORTI_PER_ARCO = 3

CARATTERI_LUCENE = re.compile(r'([+\-!(){}\[\]^"~*?:\\/|&])')
SERRATURA_EMBEDDING = threading.Lock()


def _testo_per_indice(domanda: str) -> str:
    """Protegge i caratteri che l'indice full-text leggerebbe come operatori."""
    return CARATTERI_LUCENE.sub(r"\\\1", domanda)


@lru_cache(maxsize=32)
def _calcola_embedding_domanda(domanda: str) -> tuple[float, ...]:
    """Memorizza pochi vettori recenti in una forma che nessuno può modificare."""
    return tuple(genera_embedding_domanda(domanda))


def _embedding_domanda(domanda: str) -> list[float]:
    """Calcola una sola volta lo stesso vettore richiesto dai rami paralleli."""
    with SERRATURA_EMBEDDING:
        return list(_calcola_embedding_domanda(domanda))


ETICHETTA_PER_IDENTIFICATIVO = {
    TipoIdentificativo.TECNICA: "AttackTechnique",
    TipoIdentificativo.GRUPPO: "ThreatActor",
    TipoIdentificativo.SOFTWARE: "MalwareFamily",
}

CAMPO_IMPRONTA = {
    TipoIndicatore.HASH_MD5: "md5",
    TipoIndicatore.HASH_SHA1: "sha1",
    TipoIndicatore.HASH_SHA256: "id",
}


class Configurazione(BaseModel):
    """Ciò che distingue uno specialista dagli altri."""

    id: str
    nome: str
    descrizione: str
    etichette: tuple[str, ...]
    etichette_vettoriali: tuple[str, ...]


CONFIGURAZIONI = {
    "ioc": Configurazione(
        id="ioc",
        nome="Indicatori di compromissione",
        descrizione=(
            "Indicatori tecnici osservati dalle fonti. Si cercano per valore "
            "esatto, perché indirizzi, URL e impronte non hanno una similarità "
            "semantica utile."
        ),
        etichette=("Indicator",),
        etichette_vettoriali=(),
    ),
    "malware": Configurazione(
        id="malware",
        nome="Malware e campioni",
        descrizione=(
            "Campioni di codice malevolo e famiglie attribuite dalle fonti. "
            "Si cercano per impronta, nome, alias e descrizione."
        ),
        etichette=("MalwareSample", "MalwareFamily", "ThreatReport"),
        etichette_vettoriali=("MalwareFamily", "ThreatReport"),
    ),
    "attori": Configurazione(
        id="attori",
        nome="Attori e tecniche ATT&CK",
        descrizione=(
            "Gruppi di attacco, tecniche ATT&CK e report che li citano. "
            "Si cercano per identificativo, nome, alias e descrizione."
        ),
        etichette=("ThreatActor", "AttackTechnique", "ThreatReport"),
        etichette_vettoriali=("ThreatActor", "AttackTechnique", "ThreatReport"),
    ),
    # Il termine di paragone: tutte le etichette, tutti gli indici, nessun
    # vincolo di dominio. Identico agli altri in ogni altro aspetto.
    "generale": Configurazione(
        id="generale",
        nome="Grafo intero, senza instradamento",
        descrizione="Unione dei tre perimetri specialistici.",
        etichette=(
            "Indicator",
            "MalwareSample",
            "MalwareFamily",
            "ThreatActor",
            "AttackTechnique",
            "ThreatReport",
        ),
        etichette_vettoriali=(
            "MalwareFamily",
            "ThreatActor",
            "AttackTechnique",
            "ThreatReport",
        ),
    ),
}

DOMINI_INSTRADABILI = tuple(
    dominio for dominio in CONFIGURAZIONI if dominio != "generale"
)

NOME = (
    "coalesce(%(v)s.nome, %(v)s.titolo, %(v)s.valore, "
    "%(v)s.nome_file, %(v)s.famiglia_dichiarata, %(v)s.tipo_minaccia, "
    "%(v)s.sha256, %(v)s.fonte, %(v)s.id)"
)

CARATTERI_DESCRIZIONE = 600


def _contenuto(variabile: str) -> str:
    """Restituisce nome e, quando presente, una descrizione breve."""
    nome = NOME % {"v": variabile}
    return (
        f"CASE WHEN {variabile}.descrizione IS NULL THEN {nome} "
        f"ELSE {nome} + ' — ' + left({variabile}.descrizione, {CARATTERI_DESCRIZIONE}) END"
    )


# Priorità degli archi semantici. Le provenienze hanno un limite separato.
PRIORITA_ARCHI = (
    "CASE type(arco) "
    "  WHEN 'DERIVED_FROM'   THEN 0 "
    "  WHEN 'OBSERVES'       THEN 1 "
    "  WHEN 'SAMPLE_OF'      THEN 1 "
    "  WHEN 'INDICATES'      THEN 1 "
    "  WHEN 'USES'           THEN 1 "
    "  WHEN 'MENTIONS'       THEN 1 "
    "  WHEN 'HAS_HOST'       THEN 1 "
    "  WHEN 'CORRESPONDS_TO' THEN 2 "
    "  ELSE 3 "
    "END AS priorita"
)


def _mappa_arco(con_totale_provenienze: bool = False) -> str:
    """Proprietà ed estremi necessari per ricostruire una relazione orientata."""
    totale = (
        "totale_provenienze_snapshot: totale_provenienze, "
        if con_totale_provenienze
        else ""
    )
    return (
        "arco {.*, "
        "supporti: coalesce(arco.supporti, [])[..$supporti_per_arco], "
        "regole: coalesce(arco.regole, [])[..$supporti_per_arco], "
        "evidenze: coalesce(arco.evidenze, [])[..$supporti_per_arco], "
        "numero_supporti: coalesce(size(arco.supporti), 0), "
        f"{totale}"
        "relazione: type(arco), "
        "origine_etichetta: labels(origine)[0], origine_id: origine.id, "
        f"origine_descrizione: {NOME % {'v': 'origine'}}, "
        "destinazione_etichetta: labels(destinazione)[0], "
        "destinazione_id: destinazione.id, "
        f"destinazione_descrizione: {NOME % {'v': 'destinazione'}} "
        "}"
    )


def _clausola_evidenze(variabile: str) -> str:
    """Campiona le provenienze e alterna le categorie degli altri archi."""
    mappa = _mappa_arco()
    mappa_provenienza = _mappa_arco(con_totale_provenienze=True)
    return (
        f"CALL ({variabile}) {{ "
        f"  OPTIONAL MATCH ({variabile})-[tutti:DERIVED_FROM]->(snapshot:SourceSnapshot) "
        f"  WITH snapshot, count(tutti) AS totale_provenienze, "
        f"       min(tutti.percorso_record) AS primo_percorso "
        f"  OPTIONAL MATCH ({variabile})-[arco:DERIVED_FROM]->(snapshot) "
        f"  WHERE arco.percorso_record = primo_percorso "
        f"  WITH snapshot, arco, totale_provenienze, "
        f"       startNode(arco) AS origine, endNode(arco) AS destinazione "
        f"  ORDER BY snapshot.id "
        f"  RETURN [voce IN collect(CASE WHEN arco IS NULL THEN NULL ELSE {mappa_provenienza} END) "
        f"          WHERE voce IS NOT NULL] AS provenienze "
        f"}} "
        f"CALL ({variabile}) {{ "
        f"  OPTIONAL MATCH ({variabile})-[arco]-(vicino) "
        f"  WHERE type(arco) <> 'DERIVED_FROM' "
        f"  WITH arco, vicino, startNode(arco) AS origine, "
        f"       endNode(arco) AS destinazione, "
        f"       CASE WHEN startNode(arco) = {variabile} "
        f"            THEN 'uscita' ELSE 'entrata' END AS direzione, "
        f"       {PRIORITA_ARCHI} "
        f"  ORDER BY priorita, type(arco), labels(vicino)[0], direzione, vicino.id "
        f"  WITH priorita, type(arco) AS tipo, labels(vicino)[0] AS etichetta, "
        f"       direzione, "
        f"       collect(CASE WHEN arco IS NULL THEN NULL ELSE {mappa} END)"
        f"         [..$archi_per_nodo] AS archi "
        f"  WITH collect({{categoria: tipo + '|' + etichetta + '|' + direzione, "
        f"                priorita: priorita, "
        f"                archi: [voce IN archi WHERE voce IS NOT NULL]}}) AS gruppi "
        f"  UNWIND range(0, $archi_per_nodo - 1) AS posizione "
        f"  UNWIND gruppi AS gruppo "
        f"  WITH posizione, gruppo "
        f"  WHERE posizione < size(gruppo.archi) "
        f"  ORDER BY posizione, gruppo.priorita, gruppo.categoria "
        f"  LIMIT $archi_per_nodo "
        f"  RETURN collect(gruppo.archi[posizione]) AS semantiche "
        f"}} "
        f"WITH {variabile}, punteggio, modo, provenienze + semantiche AS evidenze"
    )


def _clausola_risultato(variabile: str) -> str:
    """Forma comune delle righe restituite dai modi di ricerca."""
    return (
        f"RETURN {_contenuto(variabile)} AS contenuto, {{ "
        f"  id: {variabile}.id, etichetta: labels({variabile})[0], "
        f"  dominio: $dominio, modo: modo, punteggio: punteggio, evidenze: evidenze "
        f"}} AS metadata"
    )


class Specialista(Retriever):
    """Recupera dal grafo entro il perimetro della propria configurazione.

    Applica i modi di ricerca che la configurazione concede, ne fonde i
    risultati e restituisce, accanto a ciascuno, gli archi che lo giustificano.
    """

    def __init__(self, driver: Driver, configurazione: Configurazione):
        super().__init__(driver)
        self.configurazione = configurazione
        # Il pacchetto usa questo attributo per identificare il recuperatore
        # nei propri messaggi. Qui non c'e un indice solo, ce ne sono fino a
        # quattro, e il nome del dominio e l'identificazione piu utile.
        self.index_name = configurazione.id

    def default_record_formatter(self, record: Record) -> RetrieverResultItem:
        return RetrieverResultItem(
            content=record.get("contenuto"), metadata=record.get("metadata")
        )

    def _esegui(self, interrogazione: str, **parametri) -> list[Record]:
        parametri.setdefault("dominio", self.configurazione.id)
        parametri.setdefault("archi_per_nodo", ARCHI_PER_NODO)
        parametri.setdefault("supporti_per_arco", SUPPORTI_PER_ARCO)
        parametri.setdefault("quanti", RISULTATI_PER_CANALE)
        return self.driver.execute_query(interrogazione, parametri).records

    def cerca_esatto(self, riconosciuti: list[Riconosciuto]) -> list[Record]:
        """Recupera i nodi che portano esattamente i valori nominati dalla domanda."""
        righe = []
        for elemento in riconosciuti:
            for etichetta, condizione, parametri in self._bersagli(elemento):
                if etichetta not in self.configurazione.etichette:
                    continue
                interrogazione = (
                    f"MATCH (n:{etichetta}) WHERE {condizione}"
                    " "
                    f"WITH n, 1.0 AS punteggio, 'esatta' AS modo "
                    f"{_clausola_evidenze('n')} "
                    f"{_clausola_risultato('n')}"
                )
                righe.extend(self._esegui(interrogazione, **parametri))
        return righe

    def _bersagli(self, elemento: Riconosciuto):
        """Restituisce i campi esatti compatibili con il tipo riconosciuto."""
        if isinstance(elemento.tipo, TipoIdentificativo):
            etichetta = ETICHETTA_PER_IDENTIFICATIVO[elemento.tipo]
            yield etichetta, "n.id = $valore", {"valore": elemento.valore}
            return

        yield (
            "Indicator",
            "n.tipo = $tipo AND n.valore = $valore",
            {
                "tipo": elemento.tipo.value,
                "valore": elemento.valore,
            },
        )
        campo = CAMPO_IMPRONTA.get(elemento.tipo)
        if campo:
            yield "MalwareSample", f"n.{campo} = $valore", {"valore": elemento.valore}

    def cerca_testuale(self, domanda: str) -> list[Record]:
        """Restituisce fino a cinque risultati per ogni etichetta ammessa."""
        righe = []
        for etichetta in self.configurazione.etichette:
            indice = INDICI_TESTUALI.get(etichetta)
            if indice is None:
                continue
            interrogazione = (
                f"CALL db.index.fulltext.queryNodes('{indice}', $testo) "
                f"YIELD node AS n, score AS punteggio "
                f"WITH n, punteggio, 'testuale' AS modo "
                f"ORDER BY punteggio DESC, labels(n)[0], n.id "
                f"LIMIT $quanti "
                f"{_clausola_evidenze('n')} "
                f"{_clausola_risultato('n')}"
            )
            righe.extend(self._esegui(interrogazione, testo=_testo_per_indice(domanda)))
        return righe

    def cerca_vettoriale(self, domanda: str) -> list[Record]:
        """Recupera per similarità, un indice per ogni etichetta concessa."""
        if not self.configurazione.etichette_vettoriali:
            return []
        vettore = _embedding_domanda(domanda)
        righe = []
        for etichetta in self.configurazione.etichette_vettoriali:
            indice = f"indice_vettoriale_{etichetta.lower()}"
            interrogazione = (
                f"MATCH (n:{etichetta}) "
                f"SEARCH n IN (VECTOR INDEX {indice} FOR $vettore LIMIT $quanti) "
                f"SCORE AS punteggio "
                f"WITH n, punteggio, 'vettoriale' AS modo "
                f"{_clausola_evidenze('n')} "
                f"{_clausola_risultato('n')}"
            )
            righe.extend(self._esegui(interrogazione, vettore=vettore))
        return righe

    def get_search_results(
        self, query_text: str, riconosciuti: list[Riconosciuto] | None = None
    ) -> RawSearchResult:
        """Applica i modi concessi, ne fonde gli esiti e li ordina."""
        riconosciuti = (
            riconosciuti if riconosciuti is not None else riconosci(query_text)
        )

        righe = self.cerca_esatto(riconosciuti)
        righe.extend(self.cerca_testuale(query_text))
        righe.extend(self.cerca_vettoriale(query_text))

        unite = _fondi(righe)
        return RawSearchResult(records=unite)


# L'ordine in cui i modi di ricerca prevalgono a parità di punteggio. Una
# corrispondenza esatta non va mai posposta a una somiglianza: chi nomina
# un'impronta vuole quel campione, non uno che le assomiglia.
PRECEDENZA_MODI = {"esatta": 0, "testuale": 1, "vettoriale": 2}


def _fondi(righe: list[Record]) -> list[Record]:
    """Deduplica, limita e alterna le etichette senza confrontare i canali."""
    migliori: dict[tuple[str, str], Record] = {}
    for riga in righe:
        dati = riga["metadata"]
        chiave = (dati["etichetta"], dati["id"])
        precedente = migliori.get(chiave)
        if precedente is None or _migliore_occorrenza(dati) < _migliore_occorrenza(
            precedente["metadata"]
        ):
            migliori[chiave] = riga

    ordinate = []
    for modo in PRECEDENZA_MODI:
        canali: dict[str, list[Record]] = {}
        for riga in migliori.values():
            dati = riga["metadata"]
            if dati["modo"] == modo:
                canali.setdefault(dati["etichetta"], []).append(riga)
        for righe_canale in canali.values():
            righe_canale.sort(key=lambda r: _rango_nel_canale(r["metadata"]))
            del righe_canale[RISULTATI_PER_CANALE:]
        for posizione in range(max(map(len, canali.values()), default=0)):
            for etichetta in sorted(canali):
                if posizione < len(canali[etichetta]):
                    ordinate.append(canali[etichetta][posizione])
    return ordinate


def _rango_nel_canale(dati: dict) -> tuple:
    return (-dati["punteggio"], dati["etichetta"], dati["id"])


def _migliore_occorrenza(dati: dict) -> tuple:
    return (PRECEDENZA_MODI[dati["modo"]],) + _rango_nel_canale(dati)


def apri_specialista(driver: Driver, dominio: str) -> Specialista:
    """Costruisce il recuperatore di un dominio, o quello generale."""
    if dominio not in CONFIGURAZIONI:
        raise ValueError(f"dominio {dominio!r}: previsti {sorted(CONFIGURAZIONI)}")
    return Specialista(driver, CONFIGURAZIONI[dominio])
