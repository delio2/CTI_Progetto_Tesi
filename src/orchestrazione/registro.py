"""Registrazione delle esecuzioni dell'orchestratore, una riga per domanda."""

import json
from datetime import datetime, timezone
from pathlib import Path
from orchestrazione.modello import (
    FINESTRA_CONTESTO,
    RAGIONAMENTO,
    SEME,
    TEMPERATURA,
    nome_modello,
)
from orchestrazione.stato import StatoOrchestrazione

CARTELLA_LOG = Path("logs")
NOME_FILE = "esecuzioni.jsonl"


def componi_riga(
    stato: StatoOrchestrazione,
    millisecondi: int,
    ordine_esecuzione: int | None = None,
) -> dict:
    """Serializza percorso, parametri ed esito di un'esecuzione."""
    return {
        "istante": datetime.now(timezone.utc).isoformat(),
        "configurazione": stato.configurazione,
        "modello": nome_modello(),
        "temperatura": TEMPERATURA,
        "seme": SEME,
        "ragionamento": RAGIONAMENTO,
        "finestra_contesto": FINESTRA_CONTESTO,
        "ordine_esecuzione": ordine_esecuzione,
        "domanda": stato.domanda,
        "domanda_recupero": stato.domanda_recupero,
        "riconosciuti": [
            {"tipo": elemento.tipo.value, "valore": elemento.valore}
            for elemento in stato.riconosciuti
        ],
        "domini_attivati": stato.domini,
        "modi_impiegati": sorted({evidenza.modo for evidenza in stato.evidenze}),
        # Prima e dopo la fusione: la differenza fra i due numeri è la quota di
        # ripetizioni fra specialisti, che su una domanda trasversale è il dato
        # che dice se la fusione sta servendo a qualcosa.
        "recuperate": len(stato.recuperate),
        "evidenze": [evidenza.model_dump(mode="json") for evidenza in stato.evidenze],
        "risposta": stato.risposta,
        "millisecondi": millisecondi,
    }


def registra(
    stato: StatoOrchestrazione,
    millisecondi: int,
    cartella: Path = CARTELLA_LOG,
    ordine_esecuzione: int | None = None,
) -> dict:
    """Accoda l'esecuzione al registro e restituisce la riga scritta."""
    # Qui si accoda invece di riscrivere, al contrario di quanto fanno gli altri
    # livelli della pipeline: il registro non è un prodotto rigenerabile dallo
    # snapshot, è il verbale di ciò che è accaduto.
    cartella.mkdir(parents=True, exist_ok=True)
    riga = componi_riga(stato, millisecondi, ordine_esecuzione)
    with open(
        cartella / NOME_FILE, "a", encoding="utf-8", newline="\n"
    ) as file_registro:
        file_registro.write(json.dumps(riga, ensure_ascii=False) + "\n")
    return riga
