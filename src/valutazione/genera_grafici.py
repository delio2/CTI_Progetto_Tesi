"""Genera i grafici della valutazione deterministica e umana."""

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

CARTELLA = Path("valutazione")
PERCORSO_METRICHE = CARTELLA / "valutazione_deterministica.json"
PERCORSO_UMANA = CARTELLA / "valutazione_umana.csv"
PERCORSO_CASI = CARTELLA / "casi.jsonl"
CARTELLA_GRAFICI = CARTELLA / "grafici"
SCELTE = ("router", "generale", "parita", "entrambe_inadeguate")
PESI_INDICE = {
    "Preferenza umana": 0.40,
    "F1 del recupero": 0.25,
    "Copertura delle evidenze attese citate": 0.15,
    "Risposte con citazione verificabile": 0.10,
    "Rapidita relativa": 0.10,
}

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "axes.linewidth": 0.8,
    }
)


def leggi_valutazione_umana() -> tuple[dict[str, float], dict[str, int]]:
    """Valida la tabella e assegna i punti del confronto umano."""
    casi = {
        caso["id"]: caso["domanda"]
        for riga in PERCORSO_CASI.read_text(encoding="utf-8").splitlines()
        if riga.strip()
        for caso in [json.loads(riga)]
    }
    with open(PERCORSO_UMANA, encoding="utf-8", newline="") as file:
        righe = list(csv.DictReader(file, delimiter=";"))

    conteggi = {scelta: 0 for scelta in SCELTE}
    identificativi = set()
    for numero, riga in enumerate(righe, start=2):
        identificativo = (riga.get("id") or "").strip()
        if not identificativo or identificativo in identificativi:
            raise ValueError(f"riga {numero}: identificativo mancante o duplicato")
        if identificativo not in casi:
            raise ValueError(f"riga {numero}: caso sconosciuto {identificativo!r}")
        if (riga.get("domanda") or "").strip() != casi[identificativo]:
            raise ValueError(f"riga {numero}: domanda diversa dal gold set")
        identificativi.add(identificativo)
        try:
            valori = {scelta: int(riga[scelta]) for scelta in SCELTE}
        except (KeyError, TypeError, ValueError) as errore:
            raise ValueError(f"riga {numero}: usare soltanto 0 e 1") from errore
        if any(valore not in (0, 1) for valore in valori.values()):
            raise ValueError(f"riga {numero}: usare soltanto 0 e 1")
        if sum(valori.values()) != 1:
            raise ValueError(f"riga {numero}: deve esserci esattamente un 1")
        for scelta, valore in valori.items():
            conteggi[scelta] += valore

    mancanti = set(casi) - identificativi
    if mancanti:
        raise ValueError(f"mancano {len(mancanti)} giudizi umani")
    totale = len(righe)
    punteggi = {
        "router": (conteggi["router"] + conteggi["parita"]) / totale,
        "generale": (conteggi["generale"] + conteggi["parita"]) / totale,
    }
    return punteggi, conteggi


def calcola_metriche(riepilogo: dict, umana: dict[str, float]) -> dict:
    """Raccoglie le sole metriche usate nel confronto finale."""
    configurazioni = riepilogo["configurazioni"]
    latenza_minima = min(v["latenza_mediana_ms"] for v in configurazioni.values())

    metriche = {}
    for nome, dati in configurazioni.items():
        metriche[nome] = {
            "F1 del recupero": dati["f1_medio_riferimenti_attesi"],
            "Copertura delle evidenze attese citate": dati[
                "copertura_riferimenti_attesi_nelle_citazioni"
            ],
            "Risposte con citazione verificabile": dati[
                "quota_risposte_con_citazione_valida"
            ],
            "Rapidita relativa": latenza_minima / dati["latenza_mediana_ms"],
            "Preferenza umana": umana[nome],
        }
    return metriche


def calcola_indice(metriche: dict[str, float]) -> float:
    """Combina qualita, giudizio umano e rapidita con pesi dichiarati."""
    if sum(PESI_INDICE.values()) != 1:
        raise ValueError("i pesi dell'indice finale devono sommare a uno")
    return sum(metriche[nome] * peso for nome, peso in PESI_INDICE.items())


def grafico_punti(
    etichette: list[str],
    router: list[float],
    generale: list[float],
    percorso: Path,
    etichetta_asse: str = "Punteggio (%), piu alto e meglio",
    percentuali: bool = True,
) -> None:
    """Confronta due serie tramite posizione su una scala comune."""
    posizioni = list(range(len(etichette)))
    altezza = max(2.4, len(etichette) * 0.5 + 1)
    fig, ax = plt.subplots(figsize=(7.2, altezza), constrained_layout=True)
    ax.hlines(
        posizioni,
        [min(r, g) for r, g in zip(router, generale)],
        [max(r, g) for r, g in zip(router, generale)],
        color="black",
        linewidth=0.8,
        zorder=1,
    )
    ax.scatter(
        router,
        [p - 0.045 for p in posizioni],
        s=38,
        marker="o",
        facecolor="black",
        edgecolor="black",
        label="Router",
        zorder=2,
    )
    ax.scatter(
        generale,
        [p + 0.045 for p in posizioni],
        s=38,
        marker="s",
        facecolor="white",
        edgecolor="black",
        linewidth=1.0,
        label="Generale",
        zorder=2,
    )
    for posizione, valore in enumerate(router):
        ax.annotate(
            f"{valore:.1%}" if percentuali else f"{valore:.1f}",
            (valore, posizione - 0.045),
            xytext=(0, 7),
            textcoords="offset points",
            ha="center",
            fontsize=7.5,
        )
    for posizione, valore in enumerate(generale):
        ax.annotate(
            f"{valore:.1%}" if percentuali else f"{valore:.1f}",
            (valore, posizione + 0.045),
            xytext=(0, -12),
            textcoords="offset points",
            ha="center",
            fontsize=7.5,
        )

    ax.set_yticks(posizioni, etichette)
    ax.set_ylim(len(etichette) - 0.55, -0.55)
    massimo = max(router + generale)
    ax.set_xlim(0, 1.04 if percentuali else massimo * 1.12)
    if percentuali:
        ax.xaxis.set_major_formatter(PercentFormatter(1))
    ax.set_xlabel(etichetta_asse)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=2, frameon=False)
    fig.savefig(percorso, dpi=300, facecolor="white")
    plt.close(fig)


def salva_confronto(metriche: dict[str, dict[str, float]]) -> None:
    """Disegna le tre misure automatiche di qualita e quella umana."""
    etichette = [
        "F1 del recupero",
        "Copertura delle evidenze attese citate",
        "Risposte con citazione verificabile",
        "Preferenza umana",
    ]
    grafico_punti(
        etichette,
        [metriche["router"][nome] for nome in etichette],
        [metriche["generale"][nome] for nome in etichette],
        CARTELLA_GRAFICI / "confronto_metriche.png",
    )


def salva_indice_finale(metriche: dict[str, dict[str, float]], conteggi: dict[str, int]):
    """Disegna l'indice pesato delle cinque metriche di confronto."""
    router = calcola_indice(metriche["router"])
    generale = calcola_indice(metriche["generale"])
    grafico_punti(
        ["Indice finale"],
        [router],
        [generale],
        CARTELLA_GRAFICI / "indice_finale.png",
    )

    print(f"router: indice finale {router * 100:.1f}")
    print(f"generale: indice finale {generale * 100:.1f}")
    print(
        "giudizi: "
        f"router {conteggi['router']}, generale {conteggi['generale']}, "
        f"parita {conteggi['parita']}, "
        f"entrambe inadeguate {conteggi['entrambe_inadeguate']}"
    )


def salva_valori_grezzi(riepilogo: dict) -> None:
    """Separa latenza mediana ed evidenze medie dall'indice normalizzato."""
    router = riepilogo["configurazioni"]["router"]
    generale = riepilogo["configurazioni"]["generale"]
    grafico_punti(
        ["Tempo mediano"],
        [router["latenza_mediana_ms"] / 1000],
        [generale["latenza_mediana_ms"] / 1000],
        CARTELLA_GRAFICI / "tempo_risposta.png",
        "Tempo (s), piu basso e meglio",
        percentuali=False,
    )
    grafico_punti(
        ["Evidenze medie"],
        [router["evidenze_medie"]],
        [generale["evidenze_medie"]],
        CARTELLA_GRAFICI / "evidenze_recuperate.png",
        "Numero medio di evidenze per risposta",
        percentuali=False,
    )


def genera_grafici() -> None:
    riepilogo = json.loads(PERCORSO_METRICHE.read_text(encoding="utf-8"))
    umana, conteggi = leggi_valutazione_umana()
    if sum(conteggi.values()) != riepilogo["numero_casi"]:
        raise ValueError("la valutazione umana non contiene tutti i casi")
    metriche = calcola_metriche(riepilogo, umana)
    CARTELLA_GRAFICI.mkdir(parents=True, exist_ok=True)
    salva_confronto(metriche)
    salva_indice_finale(metriche, conteggi)
    salva_valori_grezzi(riepilogo)


if __name__ == "__main__":
    genera_grafici()
