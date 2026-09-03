"""Controlli essenziali delle regole deterministiche e della loro integrità."""

import hashlib
import json
from pathlib import Path

import pytest

from grafo_conoscenza import esegui_caricamento
from grafo_conoscenza.esegui_correlazione import MODELLO_PER_FILE, deduplica, esegui
from grafo_conoscenza.integrita import ElaborazioneIncoerente, verifica_correlazione
from grafo_conoscenza.relazioni import (
    genera_corresponds_to_alias,
    genera_corresponds_to_impronta,
    genera_has_host,
    genera_indicates,
    genera_mentions,
    genera_sample_of,
    genera_uses_attribuzione,
    relazione,
)
from grafo_conoscenza.relazioni_attack import (
    genera_sostituzioni_tecniche,
    trova_bundle_attack,
)
from normalizzazione import parser_otx, parser_urlhaus
from normalizzazione.esegui_normalizzazione import esegui as normalizza
from normalizzazione.io_snapshot import calcola_impronta, calcola_impronte
from normalizzazione.modelli import (
    AttackTechnique,
    Indicator,
    MalwareFamily,
    MalwareSample,
    Observation,
    RiferimentoGrezzo,
    SourceSnapshot,
    ThreatActor,
    ThreatReport,
)
from normalizzazione.vocabolari import TipoIndicatore

FIXTURES = Path(__file__).parent.parent / "normalizzazione" / "fixtures"
FIXTURE_ATTACK = Path(__file__).parent / "fixtures" / "mitre_relazioni_campione.json"
SEI_FONTI = [
    ("ThreatFox", FIXTURES / "threatfox_campione.json"),
    ("MalwareBazaar", FIXTURES / "malwarebazaar_campione.csv"),
    ("URLhaus", FIXTURES / "urlhaus_campione.json"),
    ("AlienVault OTX (subscribed)", FIXTURES / "otx_subscribed_campione.json"),
    ("MITRE ATT&CK", FIXTURE_ATTACK),
    ("Malpedia", FIXTURES / "malpedia_campione.json"),
]


def riferimento(percorso="data[0]", snapshot="prova"):
    return RiferimentoGrezzo(id_snapshot=snapshot, percorso_record=percorso)


def famiglia(identificativo, nome, snapshot="prova", **campi):
    provenienza = riferimento(snapshot=snapshot)
    alias = campi.get("alias", [])
    campi.setdefault("provenienze_alias", {a: [provenienza] for a in alias})
    return MalwareFamily(
        id=identificativo,
        nome=nome,
        origini=campi.pop("origini", ["operativa"]),
        provenienze=[provenienza],
        **campi,
    )


def leggi_jsonl(percorso):
    return [
        json.loads(riga) for riga in percorso.read_text(encoding="utf-8").splitlines()
    ]


def test_le_regole_collegano_solo_entita_compatibili():
    mirai = famiglia("mirai", "Mirai")
    osservazione = Observation(
        id="o1",
        id_indicator="i1",
        fonte="Prova",
        famiglia_dichiarata="Mirai",
        provenienze=[riferimento()],
    )
    campione = MalwareSample(
        id="a" * 64,
        sha256="a" * 64,
        famiglia_dichiarata="Mirai",
        provenienze=[riferimento()],
    )
    assert genera_indicates([osservazione], [mirai])[0].id_destinazione == "mirai"
    assert genera_sample_of([campione], [mirai])[0].id_destinazione == "mirai"

    valore = "b" * 32
    campioni = [
        MalwareSample(
            id="md5", sha256="1" * 64, md5=valore, provenienze=[riferimento()]
        ),
        MalwareSample(
            id="sha1", sha256="2" * 64, sha1=valore, provenienze=[riferimento()]
        ),
    ]
    indicatore = Indicator(
        id="i",
        tipo=TipoIndicatore.HASH_MD5,
        valore=valore,
        provenienze=[riferimento()],
    )
    assert [
        arco.id_destinazione
        for arco in genera_corresponds_to_impronta([indicatore], campioni)
    ] == ["md5"]

    generica = osservazione.model_copy(
        update={"famiglia_dichiarata": None, "etichette": ["rat"]}
    )
    assert genera_indicates([generica], [famiglia("rat", "RAT")]) == []


def test_alias_e_attribuzioni_usano_la_provenienza_che_li_dichiara():
    operativa = famiglia("remcosrat", "RemcosRAT", snapshot="threatfox")
    censita = famiglia(
        "S0332",
        "Remcos",
        snapshot="mitre",
        origini=["mitre-attack"],
        alias=["RemcosRAT"],
    )
    censita.provenienze.insert(0, riferimento("data[9]", "otx"))
    arco = genera_corresponds_to_alias([operativa, censita], "MalwareFamily")[0]
    assert arco.supporti == ["threatfox:data[0] <-> mitre:data[0]"]

    emotet = famiglia(
        "win.emotet",
        "Emotet",
        snapshot="malpedia",
        origini=["malpedia"],
        attribuita_a=["MUMMY SPIDER"],
    )
    emotet.provenienze.insert(0, riferimento("data[7]", "threatfox"))
    gruppo = ThreatActor(
        id="mummy-spider",
        nome="MUMMY SPIDER",
        origini=["malpedia"],
        provenienze=[riferimento(snapshot="malpedia")],
    )
    uso = genera_uses_attribuzione(
        [emotet],
        [gruppo],
        {"malpedia": "Malpedia", "threatfox": "ThreatFox"},
    )[0]
    assert uso.supporti == ["malpedia:data[0]"]

    prima = relazione(
        "INDICATES", "Indicator", "i", "MalwareFamily", "f", "o1", "r1", "e1"
    )
    seconda = relazione(
        "INDICATES", "Indicator", "i", "MalwareFamily", "f", "o2", "r2", "e2"
    )
    unica = deduplica([seconda, prima])[0]
    assert list(zip(unica.supporti, unica.regole, unica.evidenze)) == [
        ("o1", "r1", "e1"),
        ("o2", "r2", "e2"),
    ]


def test_url_report_e_tecniche_non_ereditano_contesto_indebito(tmp_path):
    urlhaus = parser_urlhaus.normalizza_file(
        FIXTURES / "urlhaus_campione.json", "urlhaus"
    )
    host = {o.id_host_derivato for o in urlhaus.osservazioni}
    assert {a.id_destinazione for a in genera_has_host(urlhaus.osservazioni)} == host
    assert all(
        a.id_origine not in host
        for a in genera_indicates(
            urlhaus.osservazioni, [famiglia("formbook", "Formbook")]
        )
    )

    otx = parser_otx.normalizza_file(FIXTURES / "otx_subscribed_campione.json", "otx")
    tecnica = AttackTechnique(
        id="T1113",
        nome="Screen Capture",
        provenienze=[riferimento(snapshot="mitre")],
    )
    menzioni = genera_mentions(
        otx.report, otx.indicatori, otx.famiglie, otx.attori, [tecnica]
    )
    assert menzioni and {a.tipo_origine for a in menzioni} == {"ThreatReport"}
    assert genera_indicates(otx.osservazioni, otx.famiglie) == []

    bundle = json.loads(FIXTURE_ATTACK.read_text(encoding="utf-8"))
    bundle["objects"].extend(
        [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--11111111-1111-4111-8111-111111111111",
                "name": "Indicator Removal from Tools",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1027.005"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--22222222-2222-4222-8222-222222222222",
                "relationship_type": "revoked-by",
                "source_ref": "attack-pattern--00d0b012-8a03-410e-95de-5826bf542de6",
                "target_ref": "attack-pattern--11111111-1111-4111-8111-111111111111",
            },
        ]
    )
    percorso = tmp_path / "attack.json"
    percorso.write_text(json.dumps(bundle), encoding="utf-8")
    sostituzioni = genera_sostituzioni_tecniche(percorso)
    report = ThreatReport(
        id="r",
        fonte="Prova",
        titolo="Report",
        tecniche_citate=["T1066"],
        provenienze=[riferimento()],
    )
    menzione = genera_mentions(
        [report],
        [],
        [],
        [],
        [
            AttackTechnique(
                id="T1027.005", nome="Sostituta", provenienze=[riferimento()]
            )
        ],
        sostituzioni,
    )[0]
    assert (menzione.id_destinazione, menzione.evidenze) == (
        "T1027.005",
        ["T1066"],
    )


def test_la_correlazione_completa_e_ripetibile_e_non_lascia_archi_sospesi(
    prepara_snapshot,
):
    grezzi, normalizzati = prepara_snapshot(SEI_FONTI)
    normalizza(grezzi, normalizzati, "manifest.json")
    esegui(grezzi, normalizzati)

    prima = (normalizzati / "relazioni.jsonl").read_bytes()
    archi = leggi_jsonl(normalizzati / "relazioni.jsonl")
    identificatori = {
        modello.__name__: {riga["id"] for riga in leggi_jsonl(normalizzati / nome_file)}
        for nome_file, modello in MODELLO_PER_FILE.items()
    }
    tracciate = {
        (a["tipo_origine"], a["id_origine"])
        for a in archi
        if a["tipo_relazione"] == "DERIVED_FROM"
    }

    assert {
        "DERIVED_FROM",
        "OBSERVES",
        "SAMPLE_OF",
        "HAS_HOST",
        "INDICATES",
        "CORRESPONDS_TO",
        "USES",
        "MENTIONS",
    } <= {a["tipo_relazione"] for a in archi}
    assert all(a["id_origine"] in identificatori[a["tipo_origine"]] for a in archi)
    assert all(
        a["id_destinazione"] in identificatori[a["tipo_destinazione"]] for a in archi
    )
    for tipo, ids in identificatori.items():
        if tipo != "SourceSnapshot":
            assert {(tipo, identificatore) for identificatore in ids} <= tracciate

    verifica_correlazione(normalizzati, tuple(MODELLO_PER_FILE))
    esegui(grezzi, normalizzati)
    assert prima == (normalizzati / "relazioni.jsonl").read_bytes()


def test_il_preflight_blocca_file_alterati_prima_di_aprire_neo4j(tmp_path, monkeypatch):
    nomi_entita = tuple(esegui_caricamento.FILE_PER_ETICHETTA.values())
    for nome_file in nomi_entita:
        (tmp_path / nome_file).write_text("{}\n", encoding="utf-8")
    normalizzazione = {
        "eseguita_il": "2026-08-30T12:00:00+00:00",
        "impronte_file": calcola_impronte(tmp_path, nomi_entita),
    }
    (tmp_path / "manifest_normalizzazione.json").write_text(
        json.dumps(normalizzazione), encoding="utf-8"
    )
    relazioni = tmp_path / "relazioni.jsonl"
    relazioni.write_text("{}\n", encoding="utf-8")
    (tmp_path / "manifest_correlazione.json").write_text(
        json.dumps(
            {
                "normalizzazione": normalizzazione,
                "relazioni": {
                    "nome_file": relazioni.name,
                    "sha256": calcola_impronta(relazioni),
                },
            }
        ),
        encoding="utf-8",
    )

    (tmp_path / nomi_entita[0]).write_text('{"alterato": true}\n', encoding="utf-8")
    monkeypatch.setattr(
        esegui_caricamento,
        "apri_driver",
        lambda: pytest.fail("Neo4j non doveva essere aperto"),
    )
    with pytest.raises(ElaborazioneIncoerente):
        esegui_caricamento.esegui(tmp_path)


def test_il_bundle_attack_appartiene_allo_snapshot_normalizzato(tmp_path):
    vecchio = tmp_path / "attack_vecchio.json"
    recente = tmp_path / "attack_recente.json"
    vecchio.write_text('{"type":"bundle","objects":[]}', encoding="utf-8")
    recente.write_text('{"type":"bundle","objects":[{"id":"altro"}]}', encoding="utf-8")
    contenuto = vecchio.read_bytes()
    snapshot = SourceSnapshot(
        id="mitre_attack_vecchio",
        fonte="MITRE ATT&CK",
        url="https://example.test/attack.json",
        acquisito_il="2026-08-26T10:38:59Z",
        nome_file=vecchio.name,
        sha256=hashlib.sha256(contenuto).hexdigest(),
        dimensione_byte=len(contenuto),
    )
    assert trova_bundle_attack(tmp_path, [snapshot]) == vecchio
