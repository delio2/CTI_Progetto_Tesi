"""Normalizzazione del bundle STIX di MITRE ATT&CK."""

import json
from pathlib import Path
from normalizzazione.modelli import (
    AttackTechnique,
    MalwareFamily,
    RiferimentoGrezzo,
    RisultatoNormalizzazione,
    ThreatActor,
)

# Fra i riferimenti esterni, quello con questo nome porta l'identificativo
# permanente dell'oggetto (T1055.011, S0061, G0082).
CATALOGO_UFFICIALE = "mitre-attack"

TIPI_TRADOTTI = ("attack-pattern", "malware", "tool", "intrusion-set")


class BundleNonValido(Exception):
    """Il file non è un bundle STIX."""


def leggi_identificativo(oggetto: dict) -> str | None:
    """Estrae l'identificativo permanente assegnato da ATT&CK."""
    for riferimento in oggetto.get("external_references", []):
        if riferimento.get("source_name") == CATALOGO_UFFICIALE:
            return riferimento.get("external_id")
    return None


def leggi_alias(oggetto: dict) -> list[str]:
    """Estrae gli alias dal campo ufficiale previsto per il tipo STIX."""
    campo = "aliases" if oggetto.get("type") == "intrusion-set" else "x_mitre_aliases"
    nome_principale = (oggetto.get("name") or "").casefold()
    alias = []
    for voce in oggetto.get(campo) or []:
        pulita = voce.strip()
        if pulita and pulita.casefold() != nome_principale and pulita not in alias:
            alias.append(pulita)
    return alias


def e_superato(oggetto: dict) -> bool:
    """Indica se ATT&CK ha ritirato l'oggetto o lo ha sostituito."""
    return bool(oggetto.get("revoked") or oggetto.get("x_mitre_deprecated"))


def leggi_tattiche(oggetto: dict) -> list[str]:
    """Estrae le tattiche di una tecnica dalle fasi della kill chain."""
    return [
        fase["phase_name"]
        for fase in oggetto.get("kill_chain_phases", [])
        if fase.get("kill_chain_name") == CATALOGO_UFFICIALE  # scarta altre kill chain
    ]


def normalizza_file(percorso: Path, id_snapshot: str) -> RisultatoNormalizzazione:
    """Normalizza il bundle di ATT&CK."""
    # Gli oggetti ritirati o sostituiti vengono contati ma non tradotti: farli
    # entrare nel grafo significherebbe descrivere tecniche che ATT&CK non
    # riconosce più.
    with open(percorso, encoding="utf-8") as file_grezzo:
        bundle = json.load(file_grezzo)

    if bundle.get("type") != "bundle" or "objects" not in bundle:
        raise BundleNonValido(f"{percorso}: non è un bundle STIX")

    risultato = RisultatoNormalizzazione()

    for indice, oggetto in enumerate(bundle["objects"]):
        tipo_stix = oggetto.get("type")
        if tipo_stix not in TIPI_TRADOTTI:
            continue

        risultato.record_letti += 1
        identificativo = leggi_identificativo(oggetto)
        if e_superato(oggetto) or not identificativo:
            risultato.record_scartati += 1
            continue

        riferimento = RiferimentoGrezzo(
            id_snapshot=id_snapshot,
            percorso_record=f"objects[{indice}]",
            identificativo_naturale=identificativo,
        )

        if tipo_stix == "attack-pattern":
            risultato.tecniche.append(
                AttackTechnique(
                    id=identificativo,
                    nome=oggetto["name"],
                    descrizione=oggetto.get("description"),
                    e_sottotecnica=bool(oggetto.get("x_mitre_is_subtechnique")),
                    tattiche=leggi_tattiche(oggetto),
                    piattaforme=oggetto.get("x_mitre_platforms") or [],
                    provenienze=[riferimento],
                )
            )
        elif tipo_stix == "intrusion-set":
            alias = leggi_alias(oggetto)
            risultato.attori.append(
                ThreatActor(
                    id=identificativo,
                    nome=oggetto["name"],
                    origini=["mitre-attack"],
                    alias=alias,
                    provenienze_alias={voce: [riferimento] for voce in alias},
                    descrizione=oggetto.get("description"),
                    provenienze=[riferimento],
                )
            )
        else:
            # Il modello canonico non prevede un nodo per gli strumenti: il campo
            # tipo_mitre conserva la distinzione senza aggiungere entità fuori
            # dallo schema approvato.
            alias = leggi_alias(oggetto)
            risultato.famiglie.append(
                MalwareFamily(
                    id=identificativo,
                    nome=oggetto["name"],
                    origini=["mitre-attack"],
                    alias=alias,
                    provenienze_alias={voce: [riferimento] for voce in alias},
                    tipo_mitre=tipo_stix,
                    piattaforme=oggetto.get("x_mitre_platforms") or [],
                    descrizione=oggetto.get("description"),
                    provenienze=[riferimento],
                )
            )

    return risultato
