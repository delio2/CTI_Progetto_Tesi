"""Rappresentazioni vettoriali dei contenuti testuali del grafo di conoscenza."""

import threading

import torch
from sentence_transformers import SentenceTransformer

# Scelto confrontando otto modelli su mille descrizioni ATT&CK annotate.
NOME_MODELLO = "Qwen/Qwen3-Embedding-0.6B"
DIMENSIONI = 1024
DISPOSITIVO = "cuda"

# Sul Victus, lotti più grandi esauriscono gli 8 GB di VRAM con i testi Malpedia.
TESTI_PER_LOTTO = 8

# Qwen3-Embedding richiede l'istruzione solo per le domande, non per i contenuti.
PREFISSO_DOMANDA = (
    "Instruct: Given a question about cyber threats, retrieve the description "
    "of the entity that answers it\nQuery: "
)

modello_in_memoria = None
serratura_caricamento = threading.Lock()


def carica_modello() -> SentenceTransformer:
    """Carica il modello la prima volta che serve, poi lo riusa."""
    global modello_in_memoria
    with serratura_caricamento:
        if modello_in_memoria is None:
            if not torch.cuda.is_available():
                raise RuntimeError(
                    "CUDA non disponibile: verificare PyTorch e il driver NVIDIA del Victus"
                )
            modello_in_memoria = SentenceTransformer(NOME_MODELLO, device=DISPOSITIVO)
    return modello_in_memoria


def genera_embedding(testi: list[str]) -> list[list[float]]:
    """Vettorializza i testi destinati all'indice, nell'ordine ricevuto."""
    if not testi:
        return []
    vettori = carica_modello().encode(
        testi,
        batch_size=TESTI_PER_LOTTO,
        normalize_embeddings=True,
        show_progress_bar=False,
    )
    return [vettore.tolist() for vettore in vettori]


def genera_embedding_domanda(domanda: str) -> list[float]:
    """Vettorializza una domanda, anteponendole l'istruzione che ne dichiara lo scopo."""
    vettore = carica_modello().encode(
        PREFISSO_DOMANDA + domanda, normalize_embeddings=True, show_progress_bar=False
    )
    return vettore.tolist()
