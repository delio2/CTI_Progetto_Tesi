"""Chat dimostrativa: la stessa domanda alle due configurazioni, affiancate."""

import streamlit as st
from neo4j.exceptions import DriverError, Neo4jError
from ollama import ResponseError
from grafo_conoscenza.connessione import PasswordMancante, apri_driver
from orchestrazione.esegui_domanda import confronta, riscalda
from orchestrazione.grafo import costruisci
from orchestrazione.nodi import formatta_arco
from orchestrazione.stato import Evidenza
from recupero.specialista import CONFIGURAZIONI

# Le due configurazioni che il Capitolo 5 mette a confronto. L'ordine è quello
# in cui compaiono sullo schermo, da sinistra a destra.
TITOLI = {
    "router": "Instradamento verso gli specialisti",
    "generale": "GraphRAG generale, il termine di paragone",
}

NOMI_DOMINI = {
    identificativo: configurazione.nome
    for identificativo, configurazione in CONFIGURAZIONI.items()
}

GUASTI_GRAFO = (PasswordMancante, DriverError, Neo4jError)
GUASTI_MODELLO = (ResponseError, OSError)  # il client di Ollama alza ConnectionError
GUASTI = GUASTI_GRAFO + GUASTI_MODELLO


@st.cache_resource
def apri_grafo():
    """Mantiene grafo e driver per tutta la durata del processo Streamlit."""
    grafo = costruisci(apri_driver())
    riscalda(grafo)
    return grafo


def interroga(domanda: str, numero: int) -> dict:
    """Interroga in sequenza le configurazioni nell'ordine bilanciato."""
    return confronta(apri_grafo(), domanda, numero)


def messaggio_guasto(errore: Exception) -> str:
    """Converte gli errori dei servizi in un messaggio operativo breve."""
    if isinstance(errore, GUASTI_GRAFO):
        return (
            "Il grafo di conoscenza non risponde. Avviare Neo4j con "
            "`docker compose up -d neo4j`, e accertarsi che NEO4J_PASSWORD sia "
            "impostata nell'ambiente da cui la chat è stata lanciata."
        )
    return "Il modello locale non risponde. Avviare Ollama e riprovare."


def provenienza(evidenza: Evidenza) -> str:
    """Snapshot e posizione del record grezzo da cui deriva l'entità."""
    provenienze = []
    for arco in evidenza.archi:
        if arco.get("relazione") == "DERIVED_FROM":
            parti = [str(arco.get("destinazione_id", ""))]
            if arco.get("percorso_record"):
                parti.append(str(arco["percorso_record"]))
            if arco.get("identificativo_naturale"):
                parti.append(f"id fonte {arco['identificativo_naturale']}")
            totale = arco.get("totale_provenienze_snapshot")
            if totale and totale > 1:
                parti.append(f"{totale} record nello snapshot")
            provenienze.append(" · ".join(parti))
    return "; ".join(provenienze)


def collegamenti(evidenza: Evidenza) -> list[str]:
    """Gli archi semantici nel loro orientamento reale."""
    return [
        formatta_arco(arco)
        for arco in evidenza.archi
        if arco.get("relazione") != "DERIVED_FROM"
    ]


def testo_evidenze(evidenze: list[Evidenza]) -> str:
    """Formatta le evidenze in un solo elenco Markdown."""
    voci = []
    for evidenza in evidenze:
        punteggio = f"{evidenza.punteggio:.2f}".replace(".", ",")
        # Il contenuto va su una riga sola: un a capo dentro la descrizione di
        # un bollettino spezzerebbe l'elenco puntato a metà.
        contenuto = " ".join(evidenza.contenuto.split())
        voce = [
            f"- **`{evidenza.etichetta}:{evidenza.id}`** · *{evidenza.modo} "
            f"{punteggio}* · da {provenienza(evidenza)} — {contenuto}"
        ]
        for riga in collegamenti(evidenza):
            voce.append(f"  - {riga}")
        voci.append("\n".join(voce))
    return "\n".join(voci)


def mostra_esito(configurazione: str, esito: dict) -> None:
    """Una delle due metà dello schermo: che cosa ha risposto una configurazione."""
    stato = esito["stato"]
    with st.container(border=True):
        st.subheader(TITOLI[configurazione])

        # I domini attivati stanno in cima e non fra i dettagli: sono ciò che
        # rende visibile l'instradamento, che è l'oggetto dell'esperimento.
        domini = " · ".join(
            NOMI_DOMINI.get(dominio, dominio) for dominio in stato.domini
        )
        st.markdown(f"Domini attivati: **{domini}**")
        st.caption(
            f"{len(stato.evidenze)} evidenze su {len(stato.recuperate)} recuperate "
            f"· {esito['millisecondi'] / 1000:.1f} s"
        )
        st.markdown(stato.risposta or "_Nessuna risposta prodotta._")

        titolo = f"Le {len(stato.evidenze)} evidenze, e i collegamenti che le reggono"
        with st.expander(titolo):
            st.markdown(testo_evidenze(stato.evidenze))


def mostra_scambio(scambio: dict) -> None:
    """La domanda e le due risposte affiancate."""
    with st.chat_message("user"):
        st.write(scambio["domanda"])

    sinistra, destra = st.columns(2)
    with sinistra:
        mostra_esito("router", scambio["esiti"]["router"])
    with destra:
        mostra_esito("generale", scambio["esiti"]["generale"])


st.set_page_config(page_title="Grafo CTI", layout="wide")
st.title("Interrogazione del grafo di Cyber Threat Intelligence")
st.caption(
    "Ogni domanda va a entrambe le configurazioni che il Capitolo 5 mette a "
    "confronto, e le due risposte restano affiancate. La domanda tradotta, i "
    "domini attivati e le evidenze finiscono in logs/esecuzioni.jsonl."
)

if "conversazione" not in st.session_state:
    st.session_state.conversazione = []

for scambio in st.session_state.conversazione:
    mostra_scambio(scambio)

domanda = st.chat_input("Una domanda sulle minacce, in italiano")
if domanda:
    with st.chat_message("user"):
        st.write(domanda)
    try:
        with st.spinner("Le due configurazioni stanno rispondendo"):
            esiti = interroga(domanda, len(st.session_state.conversazione))
    except GUASTI as errore:
        st.error(messaggio_guasto(errore))
        with st.expander("Dettaglio tecnico"):
            st.code(str(errore))
    else:
        st.session_state.conversazione.append({"domanda": domanda, "esiti": esiti})
        # Si riesegue perché lo scambio venga disegnato dal ciclo di sopra, che
        # è l'unico punto in cui la conversazione si disegna.
        st.rerun()
