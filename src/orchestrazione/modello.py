"""Accesso al modello linguistico locale, servito da Ollama."""

import os

from ollama import chat
from pydantic import BaseModel

# Verificato con `ollama show`: 8,2 miliardi di parametri, Q4_K_M,
# impronta 500a1f067a9f.
MODELLO_PREDEFINITO = "qwen3:8b"
VARIABILE_MODELLO = "MODELLO_LLM"
TEMPERATURA = 0
SEME = 20260819
FINESTRA_CONTESTO = 24576
RAGIONAMENTO = False

# Senza un tetto il modello scrive finché non emette il token di fine, e su
# contesti lunghi ogni tanto entra in ripetizione e non lo emette più: allora
# riempie tutto lo spazio che resta nella finestra. Misurato su una domanda
# sugli indicatori: 13.102 token in diciotto minuti, per un testo che il
# controllo delle citazioni avrebbe comunque scartato. La risposta più lunga
# fra le 176 valide finora prodotte ne conta 268, quindi il limite è quasi sei
# volte il massimo osservato e non tocca nessuna risposta sensata: serve solo a
# rendere finita la coda della distribuzione delle latenze, che §5.2 misura.
TOKEN_MASSIMI_RISPOSTA = 1500

# Sul Victus la cache q8_0 riduce la memoria richiesta dal contesto e limita
# lo scaricamento del modello sulla CPU; Ollama deve essere riavviato con:
# OLLAMA_FLASH_ATTENTION=1
# OLLAMA_KV_CACHE_TYPE=q8_0
# Il limite lascia spazio al massimo contesto prodotto dal recupero senza usare
# la finestra teorica di 40.960 token, troppo costosa per gli 8 GB disponibili.


def nome_modello() -> str:
    """Il modello in uso, letto dall'ambiente o quello predefinito."""
    return os.environ.get(VARIABILE_MODELLO, MODELLO_PREDEFINITO)


def _opzioni() -> dict:
    return {
        "temperature": TEMPERATURA,
        "num_ctx": FINESTRA_CONTESTO,
        "seed": SEME,
        "num_predict": TOKEN_MASSIMI_RISPOSTA,
    }


def interroga(istruzione: str, richiesta: str) -> str:
    """Interroga il modello e restituisce il testo prodotto."""
    risposta = chat(
        model=nome_modello(),
        messages=[
            {"role": "system", "content": istruzione},
            {"role": "user", "content": richiesta},
        ],
        think=RAGIONAMENTO,
        options=_opzioni(),
    )
    return risposta.message.content or ""


def interroga_struttura(
    istruzione: str, richiesta: str, schema: type[BaseModel]
) -> BaseModel:
    """Interroga il modello vincolandone l'uscita a uno schema Pydantic."""
    risposta = chat(
        model=nome_modello(),
        messages=[
            {"role": "system", "content": istruzione},
            {"role": "user", "content": richiesta},
        ],
        format=schema.model_json_schema(),
        think=RAGIONAMENTO,
        options=_opzioni(),
    )
    return schema.model_validate_json(risposta.message.content)
