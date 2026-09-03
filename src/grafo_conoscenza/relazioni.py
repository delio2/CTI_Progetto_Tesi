"""Calcolo deterministico delle relazioni fra le entità canoniche."""

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from normalizzazione.modelli import (
    AttackTechnique,
    Indicator,
    MalwareFamily,
    MalwareSample,
    Observation,
    RiferimentoGrezzo,
    ThreatActor,
    ThreatReport,
    calcola_slug,
    estrai_id_software_attack,
)


CAMPO_IMPRONTA_PER_TIPO = {
    "hash_md5": "md5",
    "hash_sha1": "sha1",
    "hash_sha256": "sha256",
}

# Alcune fonti usano come tag categorie, piattaforme, formati o tecniche. Negli
# snapshot esistono anche omonime voci isolate nel campo "famiglia": il solo
# incontro fra i due testi non basta quindi a trasformare il tag in attribuzione.
ETICHETTE_NON_FAMIGLIA = frozenset(
    {
        "aeza",
        "apk",
        "clickfix",
        "dprk",
        "etherhiding",
        "hvnc",
        "dragonfly",
        "lazarus",
        "macos",
        "muddywater",
        "oceanlotus",
        "patchwork",
        "payload",
        "ransomware",
        "rat",
        "reverseshell",
        "sidewinder",
        "targeted",
    }
)


class RelazioneCalcolata(BaseModel):
    """Un arco e le affermazioni indipendenti che lo sostengono.

    Le tre liste sono allineate: l'elemento con indice ``i`` descrive un unico
    supporto, la regola applicata a quel supporto e la relativa evidenza.
    """

    tipo_relazione: Literal[
        "DERIVED_FROM",
        "OBSERVES",
        "INDICATES",
        "SAMPLE_OF",
        "USES",
        "CORRESPONDS_TO",
        "MENTIONS",
        "HAS_HOST",
    ]
    tipo_origine: str
    id_origine: str
    tipo_destinazione: str
    id_destinazione: str
    supporti: list[str]
    regole: list[str]
    evidenze: list[str] = Field(default_factory=list)
    percorso_record: str | None = None
    identificativo_naturale: str | None = None

    @model_validator(mode="after")
    def verifica_supporti_allineati(self):
        if not (len(self.supporti) == len(self.regole) == len(self.evidenze)):
            raise ValueError(
                "supporti, regole ed evidenze devono avere la stessa lunghezza"
            )
        return self


def riferimento_testuale(riferimento: RiferimentoGrezzo) -> str:
    """Forma leggibile e stabile di un riferimento a un record grezzo."""
    return f"{riferimento.id_snapshot}:{riferimento.percorso_record}"


def relazione(
    tipo_relazione: str,
    tipo_origine: str,
    id_origine: str,
    tipo_destinazione: str,
    id_destinazione: str,
    supporto: str,
    regola: str,
    evidenza: str | None = None,
    **proprieta,
) -> RelazioneCalcolata:
    """Costruisce un arco con un primo supporto verificabile."""
    return RelazioneCalcolata(
        tipo_relazione=tipo_relazione,
        tipo_origine=tipo_origine,
        id_origine=id_origine,
        tipo_destinazione=tipo_destinazione,
        id_destinazione=id_destinazione,
        supporti=[supporto],
        regole=[regola],
        evidenze=[evidenza or ""],
        **proprieta,
    )


def itera_derived_from(entita: list, tipo_origine: str):
    """Produce un arco per ogni record grezzo senza accumularli in memoria."""
    for elemento in entita:
        for provenienza in elemento.provenienze:
            yield relazione(
                "DERIVED_FROM",
                tipo_origine,
                elemento.id,
                "SourceSnapshot",
                provenienza.id_snapshot,
                riferimento_testuale(provenienza),
                "provenienza registrata alla normalizzazione",
                percorso_record=provenienza.percorso_record,
                identificativo_naturale=provenienza.identificativo_naturale,
            )


def genera_derived_from(entita: list, tipo_origine: str) -> list[RelazioneCalcolata]:
    """Collega ogni entità a ciascun record grezzo da cui deriva."""
    return list(itera_derived_from(entita, tipo_origine))


def itera_observes(osservazioni: list[Observation]):
    """Produce gli archi osservazione-indicatore uno alla volta."""
    for osservazione in osservazioni:
        yield relazione(
            "OBSERVES",
            "Observation",
            osservazione.id,
            "Indicator",
            osservazione.id_indicator,
            osservazione.id,
            "riferimento diretto nel record di origine",
        )


def genera_observes(osservazioni: list[Observation]) -> list[RelazioneCalcolata]:
    """Collega ogni osservazione all'indicatore che segnala."""
    return list(itera_observes(osservazioni))


def genera_has_host(osservazioni: list[Observation]) -> list[RelazioneCalcolata]:
    """Collega un URL al suo host sintattico, senza segnalarlo come malevolo."""
    return [
        relazione(
            "HAS_HOST",
            "Indicator",
            osservazione.id_indicator,
            "Indicator",
            osservazione.id_host_derivato,
            osservazione.id,
            "host estratto dalla sintassi dell'URL",
        )
        for osservazione in osservazioni
        if osservazione.id_host_derivato
    ]


def genera_indicates(
    osservazioni: list[Observation], famiglie: list[MalwareFamily]
) -> list[RelazioneCalcolata]:
    """Collega un indicatore alle famiglie attribuite dalla sua osservazione."""
    famiglie_note = {famiglia.id for famiglia in famiglie}
    relazioni = []

    for osservazione in osservazioni:
        dichiarate = set()
        if osservazione.famiglia_dichiarata:
            id_famiglia = calcola_slug(osservazione.famiglia_dichiarata)
            if id_famiglia in famiglie_note:
                dichiarate.add(id_famiglia)
                relazioni.append(
                    relazione(
                        "INDICATES",
                        "Indicator",
                        osservazione.id_indicator,
                        "MalwareFamily",
                        id_famiglia,
                        osservazione.id,
                        "famiglia dichiarata dalla fonte segnalante",
                        osservazione.famiglia_dichiarata,
                    )
                )

        for etichetta in osservazione.etichette:
            id_famiglia = calcola_slug(etichetta)
            if (
                id_famiglia in ETICHETTE_NON_FAMIGLIA
                or id_famiglia not in famiglie_note
                or id_famiglia in dichiarate
            ):
                continue
            dichiarate.add(id_famiglia)
            relazioni.append(
                relazione(
                    "INDICATES",
                    "Indicator",
                    osservazione.id_indicator,
                    "MalwareFamily",
                    id_famiglia,
                    osservazione.id,
                    "etichetta che nomina una famiglia censita",
                    etichetta,
                )
            )
    return relazioni


def itera_sample_of(campioni: list[MalwareSample], famiglie: list[MalwareFamily]):
    """Produce un arco per campione, riunendo su di esso tutti i record fonte."""
    famiglie_note = {famiglia.id for famiglia in famiglie}
    for campione in campioni:
        if not campione.famiglia_dichiarata:
            continue
        id_famiglia = calcola_slug(campione.famiglia_dichiarata)
        if id_famiglia not in famiglie_note:
            continue
        supporti = sorted(
            {riferimento_testuale(provenienza) for provenienza in campione.provenienze}
        )
        arco = relazione(
            "SAMPLE_OF",
            "MalwareSample",
            campione.id,
            "MalwareFamily",
            id_famiglia,
            supporti[0],
            "firma attribuita al campione dalla fonte",
            campione.famiglia_dichiarata,
        )
        arco.supporti = supporti
        arco.regole = ["firma attribuita al campione dalla fonte"] * len(supporti)
        arco.evidenze = [campione.famiglia_dichiarata] * len(supporti)
        yield arco


def genera_sample_of(
    campioni: list[MalwareSample], famiglie: list[MalwareFamily]
) -> list[RelazioneCalcolata]:
    """Collega ogni campione alla famiglia dichiarata dalla fonte."""
    return list(itera_sample_of(campioni, famiglie))


def genera_corresponds_to_impronta(
    indicatori: list[Indicator], campioni: list[MalwareSample]
) -> list[RelazioneCalcolata]:
    """Collega un indicatore al campione con la stessa impronta e algoritmo."""
    # Gli indicatori di impronta sono poche migliaia, mentre i campioni superano
    # il milione. Indicizzare il lato piccolo evita tre grandi dizionari inutili.
    indicatori_per_impronta = {
        tipo: {
            indicatore.valore: indicatore.id
            for indicatore in indicatori
            if indicatore.tipo.value == tipo
        }
        for tipo in CAMPO_IMPRONTA_PER_TIPO
    }
    relazioni = []
    for campione in campioni:
        for tipo, campo in CAMPO_IMPRONTA_PER_TIPO.items():
            valore = getattr(campione, campo)
            id_indicatore = indicatori_per_impronta[tipo].get(valore)
            if not id_indicatore:
                continue
            relazioni.append(
                relazione(
                    "CORRESPONDS_TO",
                    "Indicator",
                    id_indicatore,
                    "MalwareSample",
                    campione.id,
                    f"{tipo}:{valore}",
                    "corrispondenza di impronta crittografica",
                    valore,
                )
            )
    return relazioni


def genera_uses_attribuzione(
    famiglie: list[MalwareFamily],
    attori: list[ThreatActor],
    fonte_per_snapshot: dict[str, str] | None = None,
) -> list[RelazioneCalcolata]:
    """Collega il gruppo alla famiglia che Malpedia gli attribuisce."""
    fonte_per_snapshot = fonte_per_snapshot or {}
    attori_noti = {attore.id for attore in attori}
    relazioni = []
    for famiglia in famiglie:
        provenienze = famiglia.provenienze
        if fonte_per_snapshot:
            provenienze = [
                riferimento
                for riferimento in provenienze
                if fonte_per_snapshot.get(riferimento.id_snapshot) == "Malpedia"
            ]
        if not provenienze:
            continue
        supporto = min(riferimento_testuale(voce) for voce in provenienze)
        for nome_attore in famiglia.attribuita_a:
            id_attore = calcola_slug(nome_attore)
            if id_attore in attori_noti:
                relazioni.append(
                    relazione(
                        "USES",
                        "ThreatActor",
                        id_attore,
                        "MalwareFamily",
                        famiglia.id,
                        supporto,
                        "attribuzione dichiarata dalla tassonomia",
                        nome_attore,
                    )
                )
    return relazioni


def _riferimento_incrociato(
    prime: list[RiferimentoGrezzo],
    seconde: list[RiferimentoGrezzo],
    fonte_per_snapshot: dict[str, str],
) -> str | None:
    """Sceglie due record di fonti diverse che sostengono il confronto."""

    def minimi_per_fonte(provenienze):
        minimi = {}
        for riferimento in provenienze:
            fonte = fonte_per_snapshot.get(
                riferimento.id_snapshot, riferimento.id_snapshot
            )
            candidato = (riferimento_testuale(riferimento), riferimento.id_snapshot)
            if fonte not in minimi or candidato < minimi[fonte]:
                minimi[fonte] = candidato
        return minimi

    prime_per_fonte = minimi_per_fonte(prime)
    seconde_per_fonte = minimi_per_fonte(seconde)
    coppie = [
        (riferimento_a, snapshot_a, riferimento_b, snapshot_b)
        for fonte_a, (riferimento_a, snapshot_a) in prime_per_fonte.items()
        for fonte_b, (riferimento_b, snapshot_b) in seconde_per_fonte.items()
        if fonte_a != fonte_b
    ]
    if not coppie:
        return None
    riferimento_a, _, riferimento_b, _ = min(coppie)
    return f"{riferimento_a} <-> {riferimento_b}"


def genera_corresponds_to_alias(
    entita: list[MalwareFamily] | list[ThreatActor],
    tipo_entita: str,
    fonte_per_snapshot: dict[str, str] | None = None,
) -> list[RelazioneCalcolata]:
    """Collega nomi e alias uguali dichiarati da fonti diverse."""
    fonte_per_snapshot = fonte_per_snapshot or {}
    per_nome = {}
    per_alias = {}
    for elemento in entita:
        per_nome.setdefault(calcola_slug(elemento.nome), []).append(elemento)
        for alias in elemento.alias:
            per_alias.setdefault(calcola_slug(alias), []).append((elemento, alias))

    relazioni = []

    def aggiungi(
        prima,
        seconda,
        regola: str,
        evidenza: str,
        provenienze_prima: list[RiferimentoGrezzo] | None = None,
        provenienze_seconda: list[RiferimentoGrezzo] | None = None,
    ) -> None:
        if prima.id == seconda.id:
            return
        supporto = _riferimento_incrociato(
            prima.provenienze if provenienze_prima is None else provenienze_prima,
            seconda.provenienze if provenienze_seconda is None else provenienze_seconda,
            fonte_per_snapshot,
        )
        if supporto is None:
            return
        id_origine, id_destinazione = sorted((prima.id, seconda.id))
        relazioni.append(
            relazione(
                "CORRESPONDS_TO",
                tipo_entita,
                id_origine,
                tipo_entita,
                id_destinazione,
                supporto,
                regola,
                evidenza,
            )
        )

    for stesso_nome in per_nome.values():
        for indice, prima in enumerate(stesso_nome):
            for seconda in stesso_nome[indice + 1 :]:
                aggiungi(
                    prima,
                    seconda,
                    "nomi canonici uguali dichiarati da fonti diverse",
                    f"{prima.nome} = {seconda.nome}",
                )

    for chiave in sorted(per_nome.keys() & per_alias.keys()):
        for entita_nome in per_nome[chiave]:
            for entita_alias, forma_alias in per_alias[chiave]:
                aggiungi(
                    entita_nome,
                    entita_alias,
                    "nome canonico uguale a un alias dichiarato da un'altra fonte",
                    f"{entita_nome.nome} = {forma_alias}",
                    provenienze_seconda=entita_alias.provenienze_alias.get(
                        forma_alias, []
                    ),
                )
    return relazioni


def genera_mentions(
    report: list[ThreatReport],
    indicatori: list[Indicator],
    famiglie: list[MalwareFamily],
    attori: list[ThreatActor],
    tecniche: list[AttackTechnique],
    sostituzioni_tecniche: dict[str, str] | None = None,
) -> list[RelazioneCalcolata]:
    """Collega ogni report alle entità che dichiara esplicitamente."""
    sostituzioni_tecniche = sostituzioni_tecniche or {}
    noti = {
        "Indicator": {elemento.id for elemento in indicatori},
        "MalwareFamily": {elemento.id for elemento in famiglie},
        "ThreatActor": {elemento.id for elemento in attori},
        "AttackTechnique": {elemento.id for elemento in tecniche},
    }
    relazioni = []

    for bollettino in report:
        citazioni = (
            (
                "Indicator",
                (
                    (id_indicatore, id_indicatore)
                    for id_indicatore in bollettino.indicatori_citati
                ),
            ),
            (
                "MalwareFamily",
                (
                    (estrai_id_software_attack(nome) or calcola_slug(nome), nome)
                    for nome in bollettino.famiglie_citate
                ),
            ),
            (
                "ThreatActor",
                ((calcola_slug(nome), nome) for nome in bollettino.attori_citati),
            ),
            (
                "AttackTechnique",
                (
                    (sostituzioni_tecniche.get(tecnica, tecnica), tecnica)
                    for tecnica in bollettino.tecniche_citate
                ),
            ),
        )
        for tipo, valori in citazioni:
            gia_citati = set()
            for identificativo, forma_originale in valori:
                if identificativo not in noti[tipo] or identificativo in gia_citati:
                    continue
                gia_citati.add(identificativo)
                relazioni.append(
                    relazione(
                        "MENTIONS",
                        "ThreatReport",
                        bollettino.id,
                        tipo,
                        identificativo,
                        bollettino.id,
                        (
                            "tecnica corrente indicata da ATT&CK per l'ID revocato citato"
                            if tipo == "AttackTechnique"
                            and identificativo != forma_originale
                            else "entità dichiarata nel report dalla fonte"
                        ),
                        forma_originale,
                    )
                )
    return relazioni
