"""Esegue i casi annotati e calcola le misure del Capitolo 5."""

import argparse
import json
import platform
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from grafo_conoscenza.connessione import apri_driver
from grafo_conoscenza.embedding import DIMENSIONI, NOME_MODELLO as MODELLO_EMBEDDING
from orchestrazione.esegui_domanda import ordine_confronto, riscalda, rispondi
from orchestrazione.grafo import costruisci
from orchestrazione.modello import (
    FINESTRA_CONTESTO,
    RAGIONAMENTO,
    SEME,
    TEMPERATURA,
    TOKEN_MASSIMI_RISPOSTA,
    nome_modello,
)
from orchestrazione.nodi import CITAZIONE

CARTELLA = Path("valutazione")
PERCORSO_CASI = CARTELLA / "casi.jsonl"
PERCORSO_RISULTATI = CARTELLA / "risultati.jsonl"
PERCORSO_RIEPILOGO = CARTELLA / "valutazione_deterministica.json"
DOMINI = ("ioc", "malware", "attori")
RIPARTIZIONE_ATTESA = {"ioc": 20, "malware": 20, "attori": 20, "trasversale": 10}
DOMINIO_PER_ETICHETTA = {
    "Indicator": "ioc",
    "MalwareSample": "malware",
    "MalwareFamily": "malware",
    "ThreatActor": "attori",
    "AttackTechnique": "attori",
}

def leggi_jsonl(percorso: Path) -> list[dict]:
    """Legge un file JSON Lines ignorando le righe vuote."""
    if not percorso.is_file():
        return []
    return [
        json.loads(riga)
        for riga in percorso.read_text(encoding="utf-8").splitlines()
        if riga.strip()
    ]


def valida_casi(casi: list[dict]) -> None:
    """Controlla che il gold set sia completo e internamente coerente."""
    identificativi = [caso.get("id") for caso in casi]
    if len(identificativi) != len(set(identificativi)):
        raise ValueError("gli identificativi dei casi devono essere univoci")
    if Counter(caso.get("gruppo") for caso in casi) != RIPARTIZIONE_ATTESA:
        raise ValueError(f"ripartizione dei casi diversa da {RIPARTIZIONE_ATTESA}")

    for caso in casi:
        domini = caso.get("domini_attesi", [])
        riferimenti = caso.get("evidenze_attese", [])
        if not caso.get("domanda") or not domini or not riferimenti:
            raise ValueError(f"{caso.get('id')}: annotazione incompleta")
        if len(domini) != len(set(domini)) or not set(domini) <= set(DOMINI):
            raise ValueError(f"{caso['id']}: domini attesi non validi")
        if len(riferimenti) != len(set(riferimenti)):
            raise ValueError(f"{caso['id']}: evidenze attese duplicate")

        domini_documentati = set()
        for riferimento in riferimenti:
            etichetta, separatore, identificatore = riferimento.partition(":")
            if not separatore or not identificatore or etichetta not in DOMINIO_PER_ETICHETTA:
                raise ValueError(f"{caso['id']}: riferimento non valido {riferimento!r}")
            domini_documentati.add(DOMINIO_PER_ETICHETTA[etichetta])
        mancanti = set(domini) - domini_documentati
        if mancanti:
            raise ValueError(
                f"{caso['id']}: nessuna evidenza attesa per {sorted(mancanti)}"
            )


def chiavi_evidenze(stato: dict) -> set[str]:
    """Le chiavi dei nodi recuperati e passati alla sintesi."""
    return {
        f"{evidenza['etichetta']}:{evidenza['id']}"
        for evidenza in stato["evidenze"]
    }


def chiavi_contesto(stato: dict) -> set[str]:
    """Le chiavi citabili: evidenze principali ed estremi dei loro archi."""
    chiavi = chiavi_evidenze(stato)
    for evidenza in stato["evidenze"]:
        for arco in evidenza.get("archi", []):
            for estremo in ("origine", "destinazione"):
                etichetta = arco.get(f"{estremo}_etichetta")
                identificatore = arco.get(f"{estremo}_id")
                if etichetta and identificatore:
                    chiavi.add(f"{etichetta}:{identificatore}")
    return chiavi


def estrai_citazioni(risposta: str | None) -> list[str]:
    """Estrae le citazioni nella forma Etichetta:id richiesta al modello."""
    return [
        f"{corrispondenza.group(1)}:{corrispondenza.group(2)}"
        for corrispondenza in CITAZIONE.finditer(risposta or "")
    ]


def media(valori: list[float]) -> float:
    """Media aritmetica, oppure zero per un insieme vuoto."""
    return statistics.fmean(valori) if valori else 0.0


def metriche_instradamento(casi: list[dict], risultati: dict) -> dict:
    """Accuratezza esatta e macro-F1 multilabel del solo router."""
    esatte = 0
    per_dominio = {}
    for dominio in DOMINI:
        veri_positivi = falsi_positivi = falsi_negativi = 0
        for caso in casi:
            attesi = set(caso["domini_attesi"])
            predetti = set(risultati[(caso["id"], "router")]["stato"]["domini"])
            veri_positivi += dominio in attesi and dominio in predetti
            falsi_positivi += dominio not in attesi and dominio in predetti
            falsi_negativi += dominio in attesi and dominio not in predetti
        precisione = veri_positivi / (veri_positivi + falsi_positivi) if veri_positivi + falsi_positivi else 0.0
        richiamo = veri_positivi / (veri_positivi + falsi_negativi) if veri_positivi + falsi_negativi else 0.0
        f1 = 2 * precisione * richiamo / (precisione + richiamo) if precisione + richiamo else 0.0
        per_dominio[dominio] = {
            "precisione": precisione,
            "richiamo": richiamo,
            "f1": f1,
            "veri_positivi": veri_positivi,
            "falsi_positivi": falsi_positivi,
            "falsi_negativi": falsi_negativi,
        }

    for caso in casi:
        predetti = risultati[(caso["id"], "router")]["stato"]["domini"]
        esatte += set(predetti) == set(caso["domini_attesi"])
    return {
        "accuratezza_esatta": esatte / len(casi),
        "macro_f1": media([dati["f1"] for dati in per_dominio.values()]),
        "per_dominio": per_dominio,
    }


def metriche_configurazione(
    configurazione: str, casi: list[dict], risultati: dict
) -> dict:
    """Misure di recupero, citazione e latenza per una configurazione."""
    f1_riferimenti = []
    quantita_evidenze = []
    latenze = []
    riferimenti_attesi = riferimenti_attesi_citati = 0
    risposte_con_citazione_valida = 0

    for caso in casi:
        riga = risultati[(caso["id"], configurazione)]
        stato = riga["stato"]
        attese = set(caso["evidenze_attese"])
        recuperate = chiavi_evidenze(stato)
        intersezione = attese & recuperate
        precisione = len(intersezione) / len(recuperate) if recuperate else 0.0
        richiamo = len(intersezione) / len(attese)
        f1_riferimenti.append(
            2 * precisione * richiamo / (precisione + richiamo)
            if precisione + richiamo
            else 0.0
        )
        quantita_evidenze.append(len(recuperate))
        latenze.append(riga["millisecondi"])

        citazioni = estrai_citazioni(stato.get("risposta"))
        valide = [chiave for chiave in citazioni if chiave in chiavi_contesto(stato)]
        riferimenti_attesi += len(attese)
        riferimenti_attesi_citati += len(attese & set(valide))
        risposte_con_citazione_valida += bool(valide)

    return {
        "f1_medio_riferimenti_attesi": media(f1_riferimenti),
        "evidenze_medie": media(quantita_evidenze),
        "copertura_riferimenti_attesi_nelle_citazioni": riferimenti_attesi_citati / riferimenti_attesi,
        "quota_risposte_con_citazione_valida": risposte_con_citazione_valida / len(casi),
        "latenza_mediana_ms": statistics.median(latenze),
    }


def calcola_riepilogo(casi: list[dict], righe: list[dict]) -> dict:
    """Calcola il riepilogo completo dai risultati grezzi."""
    valida_casi(casi)
    chiavi = [(riga["id_caso"], riga["configurazione"]) for riga in righe]
    if len(chiavi) != len(set(chiavi)):
        raise RuntimeError("i risultati contengono esecuzioni duplicate")
    risultati = dict(zip(chiavi, righe))
    attesi = {(caso["id"], configurazione) for caso in casi for configurazione in ("router", "generale")}
    mancanti = sorted(attesi - risultati.keys())
    if mancanti:
        raise RuntimeError(f"risultati incompleti: mancano {len(mancanti)} esecuzioni")
    inattesi = sorted(risultati.keys() - attesi)
    if inattesi:
        raise RuntimeError(f"risultati estranei ai casi: {len(inattesi)} esecuzioni")

    per_configurazione = {
        configurazione: metriche_configurazione(configurazione, casi, risultati)
        for configurazione in ("router", "generale")
    }
    return {
        "calcolato_il": datetime.now(timezone.utc).isoformat(),
        "numero_casi": len(casi),
        "ripartizione": dict(Counter(caso["gruppo"] for caso in casi)),
        "instradamento": metriche_instradamento(casi, risultati),
        "configurazioni": per_configurazione,
        "ambiente": {
            "python": platform.python_version(),
            "llm": nome_modello(),
            "temperatura": TEMPERATURA,
            "seme": SEME,
            "ragionamento": RAGIONAMENTO,
            "finestra_contesto": FINESTRA_CONTESTO,
            "token_massimi_risposta": TOKEN_MASSIMI_RISPOSTA,
            "modello_embedding": MODELLO_EMBEDDING,
            "dimensioni_embedding": DIMENSIONI,
        },
    }


def esegui(sovrascrivi: bool = False) -> dict:
    """Esegue le coppie mancanti e produce il riepilogo finale."""
    casi = leggi_jsonl(PERCORSO_CASI)
    if not casi:
        raise RuntimeError(f"nessun caso in {PERCORSO_CASI}")
    valida_casi(casi)

    if sovrascrivi:
        PERCORSO_RISULTATI.unlink(missing_ok=True)
        PERCORSO_RIEPILOGO.unlink(missing_ok=True)

    righe = leggi_jsonl(PERCORSO_RISULTATI)
    completate = {(riga["id_caso"], riga["configurazione"]) for riga in righe}
    da_eseguire = [
        (indice, caso, configurazione, posizione)
        for indice, caso in enumerate(casi)
        for posizione, configurazione in enumerate(ordine_confronto(indice), start=1)
        if (caso["id"], configurazione) not in completate
    ]

    if da_eseguire:
        driver = apri_driver()
        try:
            grafo = costruisci(driver)
            print("Riscaldamento del sistema...")
            riscalda(grafo)
            with open(PERCORSO_RISULTATI, "a", encoding="utf-8", newline="\n") as file_risultati:
                for numero, (indice, caso, configurazione, posizione) in enumerate(da_eseguire, start=1):
                    print(f"[{numero}/{len(da_eseguire)}] {caso['id']} - {configurazione}")
                    stato, millisecondi = rispondi(
                        grafo,
                        caso["domanda"],
                        configurazione,
                        registra_esecuzione=False,
                        ordine_esecuzione=posizione,
                    )
                    riga = {
                        "id_caso": caso["id"],
                        "configurazione": configurazione,
                        "ordine_esecuzione": posizione,
                        "millisecondi": millisecondi,
                        "stato": stato.model_dump(mode="json"),
                    }
                    file_risultati.write(json.dumps(riga, ensure_ascii=False) + "\n")
                    file_risultati.flush()
        finally:
            driver.close()

    righe = leggi_jsonl(PERCORSO_RISULTATI)
    riepilogo = calcola_riepilogo(casi, righe)
    PERCORSO_RIEPILOGO.write_text(
        json.dumps(riepilogo, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return riepilogo


def leggi_argomenti() -> argparse.Namespace:
    """Legge l'opzione che autorizza a ricominciare l'esperimento da zero."""
    lettore = argparse.ArgumentParser(description=__doc__)
    lettore.add_argument(
        "--sovrascrivi",
        action="store_true",
        help="elimina i risultati esistenti prima di eseguire i casi",
    )
    return lettore.parse_args()


if __name__ == "__main__":
    argomenti = leggi_argomenti()
    print(json.dumps(esegui(argomenti.sovrascrivi), indent=2, ensure_ascii=False))
