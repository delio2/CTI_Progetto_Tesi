"""Controlli essenziali del confine fra fonti grezze e schema canonico."""

import json
from pathlib import Path

import pytest

from normalizzazione import (
    parser_malpedia,
    parser_malwarebazaar,
    parser_mitre,
    parser_otx,
    parser_threatfox,
    parser_urlhaus,
)
from normalizzazione.esegui_normalizzazione import FILE_PER_TIPO, esegui
from normalizzazione.io_snapshot import (
    IntegritaNonVerificata,
    leggi_manifest,
    verifica_integrita,
)
from normalizzazione.vocabolari import (
    TipoIndicatore,
    ValoreIndicatoreNonValido,
    uniforma_valore,
)

FIXTURES = Path(__file__).parent / "fixtures"
SEI_FONTI = [
    ("ThreatFox", FIXTURES / "threatfox_campione.json"),
    ("MalwareBazaar", FIXTURES / "malwarebazaar_campione.csv"),
    ("URLhaus", FIXTURES / "urlhaus_campione.json"),
    ("AlienVault OTX (subscribed)", FIXTURES / "otx_subscribed_campione.json"),
    ("MITRE ATT&CK", FIXTURES / "mitre_campione.json"),
    ("Malpedia", FIXTURES / "malpedia_campione.json"),
]
PARSER = [
    (parser_threatfox, "threatfox_campione.json"),
    (parser_malwarebazaar, "malwarebazaar_campione.csv"),
    (parser_urlhaus, "urlhaus_campione.json"),
    (parser_otx, "otx_subscribed_campione.json"),
    (parser_mitre, "mitre_campione.json"),
    (parser_malpedia, "malpedia_campione.json"),
]
CAMPI_ENTITA = (
    "indicatori",
    "osservazioni",
    "campioni",
    "famiglie",
    "attori",
    "tecniche",
    "report",
)


def test_la_canonicalizzazione_modifica_solo_le_parti_equivalenti():
    casi = [
        (TipoIndicatore.DOMINIO, "Example.COM", "example.com"),
        (TipoIndicatore.DOMINIO, "keró.hu", "xn--ker-ina.hu"),
        (TipoIndicatore.HASH_MD5, "AB" * 16, "ab" * 16),
        (
            TipoIndicatore.URL,
            "HXXPS://Example.COM:443/Path/File?Value=A#",
            "https://example.com/Path/File?Value=A#",
        ),
        (
            TipoIndicatore.URL,
            "wss://Example.COM:443/Socket",
            "wss://example.com/Socket",
        ),
        (
            TipoIndicatore.URL,
            "https://keró.hu/Path",
            "https://xn--ker-ina.hu/Path",
        ),
        (TipoIndicatore.URL, "tftp://Example.COM:69/file", "tftp://example.com/file"),
    ]
    for tipo, valore, atteso in casi:
        assert uniforma_valore(tipo, valore) == atteso

    for dominio in ("a@b.test", "etichetta..test", "םv", "x" * 64 + ".test"):
        with pytest.raises(ValoreIndicatoreNonValido):
            uniforma_valore(TipoIndicatore.DOMINIO, dominio)


def test_tutti_i_parser_producono_entita_tracciabili_e_coerenti():
    for parser, nome_file in PARSER:
        risultato = parser.normalizza_file(FIXTURES / nome_file, parser.__name__)
        assert risultato.record_letti > 0

        entita = [voce for campo in CAMPI_ENTITA for voce in getattr(risultato, campo)]
        assert entita
        assert all(voce.provenienze for voce in entita)

        for voce in risultato.famiglie + risultato.attori:
            assert set(voce.provenienze_alias) == set(voce.alias)
            assert all(voce.provenienze_alias[alias] for alias in voce.alias)

        indicatori = {voce.id: voce for voce in risultato.indicatori}
        for osservazione in risultato.osservazioni:
            assert osservazione.id_indicator in indicatori
            if indicatori[osservazione.id_indicator].tipo is TipoIndicatore.URL:
                assert osservazione.id_host_derivato in indicatori

        for report in risultato.report:
            assert set(report.indicatori_citati) <= set(indicatori)


def test_i_parser_non_trasformano_segnaposto_o_contesto_in_attribuzioni():
    threatfox = parser_threatfox.normalizza_file(
        FIXTURES / "threatfox_campione.json", "threatfox"
    )
    bazaar = parser_malwarebazaar.normalizza_file(
        FIXTURES / "malwarebazaar_campione.csv", "bazaar"
    )
    otx = parser_otx.normalizza_file(FIXTURES / "otx_subscribed_campione.json", "otx")
    mitre = parser_mitre.normalizza_file(FIXTURES / "mitre_campione.json", "mitre")

    assert "Unknown malware" not in {f.nome for f in threatfox.famiglie}
    assert all(o.porta != 0 for o in threatfox.osservazioni)
    assert "n/a" not in {f.nome for f in bazaar.famiglie}
    assert all(c.id == c.sha256 for c in bazaar.campioni)
    assert all(
        o.famiglia_dichiarata is None and not o.etichette for o in otx.osservazioni
    )
    assert any(r.tecniche_citate for r in otx.report)
    assert all(f.tipo_mitre in ("malware", "tool") for f in mitre.famiglie)


def test_la_pipeline_e_ripetibile_e_conserva_ogni_provenienza(prepara_snapshot):
    grezzi, uscita = prepara_snapshot(SEI_FONTI)
    esegui(grezzi, uscita, "manifest.json")

    manifest = json.loads(
        (uscita / "manifest_normalizzazione.json").read_text(encoding="utf-8")
    )
    dichiarati = {
        json.loads(riga)["id"]
        for riga in (uscita / "source_snapshot.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    }
    prima = {p.name: p.read_bytes() for p in uscita.glob("*.jsonl")}

    condiviso = False
    for nome_file in FILE_PER_TIPO.values():
        righe = (uscita / nome_file).read_text(encoding="utf-8").splitlines()
        assert len(righe) == manifest["entita_scritte"][nome_file]
        for riga in righe:
            provenienze = json.loads(riga)["provenienze"]
            assert provenienze
            assert {p["id_snapshot"] for p in provenienze} <= dichiarati
            condiviso |= len({p["id_snapshot"] for p in provenienze}) > 1

    assert condiviso
    esegui(grezzi, uscita, "manifest.json")
    assert prima == {p.name: p.read_bytes() for p in uscita.glob("*.jsonl")}


def test_uno_snapshot_alterato_viene_rifiutato(prepara_snapshot):
    grezzi, _ = prepara_snapshot([SEI_FONTI[0]])
    snapshot = leggi_manifest(grezzi / "manifest.json")[0]
    verifica_integrita(grezzi, snapshot)

    percorso = grezzi / snapshot.nome_file
    percorso.write_text(percorso.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(IntegritaNonVerificata):
        verifica_integrita(grezzi, snapshot)
