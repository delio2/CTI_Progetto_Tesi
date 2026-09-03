# Pipeline CTI con knowledge graph e GraphRAG

Prototipo della tesi in Ingegneria Informatica. Sei fonti aperte di Cyber
Threat Intelligence vengono raccolte, normalizzate e correlate in Neo4j. Un
orchestratore LangGraph confronta un recupero instradato per dominio con un
recupero generale e genera risposte locali tramite Qwen3 e Ollama.

```text
fonti OSINT -> snapshot verificato -> entità canoniche -> correlazioni
-> Neo4j -> recupero GraphRAG -> LangGraph -> risposta con citazioni
```

Le relazioni del grafo derivano soltanto dai dati e da regole deterministiche.
Il modello linguistico traduce la domanda, partecipa al routing e sintetizza le
evidenze, ma non crea correlazioni.

## Struttura

| Percorso | Contenuto |
|---|---|
| `n8n/workflows/` | Workflow di raccolta delle sei fonti |
| `data/raw/` | Manifest versionato; snapshot completi conservati localmente |
| `data/processed/` | Entità e relazioni generate localmente |
| `src/normalizzazione/` | Parser e modelli canonici Pydantic |
| `src/grafo_conoscenza/` | Correlazione, integrità, caricamento ed embedding |
| `src/recupero/` | Ricerca esatta, testuale e vettoriale |
| `src/orchestrazione/` | Flusso LangGraph e accesso a Ollama |
| `src/interfaccia/` | Confronto affiancato in Streamlit |
| `tests/` | Ventuno controlli essenziali |
| `valutazione/` | Casi, risultati, giudizi, metriche e grafici |

## Requisiti

Configurazione verificata sul portatile HP Victus:

- Windows, Python 3.13 e Docker Desktop;
- GPU NVIDIA RTX 4060 Laptop da 8 GB;
- Ollama con `qwen3:8b`;
- Neo4j 2026.07.1 e n8n 2.23.4, avviati da Docker Compose.

La ricostruzione completa richiede anche i sei file dello snapshot, esclusi da
Git per dimensione. Sul Victus sono già presenti insieme al grafo popolato.

## Installazione

Creare `.env` e sostituire i due valori segnaposto. La chiave n8n e la password
Neo4j devono restare stabili dopo la creazione dei volumi Docker.

```powershell
Copy-Item .env.example .env
notepad .env

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[sviluppo]"
```

Sul Victus installare la versione CUDA verificata di PyTorch:

```powershell
.\.venv\Scripts\python.exe -m pip uninstall -y torch
.\.venv\Scripts\python.exe -m pip install "torch==2.11.0+cu128" --index-url https://download.pytorch.org/whl/cu128
```

Installare Ollama, configurare la cache e scaricare il modello:

```powershell
[Environment]::SetEnvironmentVariable("OLLAMA_FLASH_ATTENTION", "1", "User")
[Environment]::SetEnvironmentVariable("OLLAMA_KV_CACHE_TYPE", "q8_0", "User")
ollama pull qwen3:8b
```

Riavviare Ollama dopo avere impostato le variabili. Il progetto usa temperatura
zero, seme fisso, finestra di 24.576 token e risposte limitate a 1.500 token.

## Avvio e test

Avviare i servizi e caricare la password Neo4j nella sessione PowerShell:

```powershell
docker compose up -d
$riga = Get-Content .env | Where-Object { $_ -match '^NEO4J_PASSWORD=' } | Select-Object -First 1
$env:NEO4J_PASSWORD = $riga.Substring('NEO4J_PASSWORD='.Length).Trim('"')

.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest -q
```

Sul Victus, con il grafo caricato, il risultato atteso è `21 passed`. Le prove
verificano normalizzazione, integrità, correlazione, Neo4j reale, embedding,
recupero, routing, citazioni e formule della valutazione.

## Demo

Risposta instradata dal terminale:

```powershell
.\.venv\Scripts\python.exe -m orchestrazione.esegui_domanda "Che relazione c'è fra il gruppo G0010 e la tecnica T1055?"
```

Confronto affiancato fra router e recuperatore generale:

```powershell
.\.venv\Scripts\streamlit.exe run src\interfaccia\chat.py
```

Aprire <http://localhost:8501>. Ogni lato mostra risposta, tempo, domini,
evidenze, provenienze e relazioni. Domande utili:

```text
Che relazione c'è fra il gruppo G0010 e la tecnica T1055?
Che cosa sai dell'indirizzo 94.250.190.137?
Quale campione corrisponde a 2b223f94614fcef4ccb9e7baf6effdaf391f069b92396e256f84b4b1822ff7d1?
Quali tecniche sono associate al process injection?
```

Neo4j è disponibile su <http://localhost:7474> e n8n su
<http://localhost:5678>.

## Valutazione

I 70 casi producono 140 risposte, una per configurazione. Il primo comando usa
i risultati esistenti e completa soltanto quelli mancanti; il secondo rigenera
deliberatamente l'intero esperimento.

```powershell
.\.venv\Scripts\python.exe -m valutazione.esegui
.\.venv\Scripts\python.exe -m valutazione.esegui --sovrascrivi
```

La scelta umana si registra in `valutazione/valutazione_umana.csv` con un solo
`1` per riga:

- `router`: la risposta instradata è complessivamente migliore;
- `generale`: la risposta generale è complessivamente migliore;
- `parita`: le due risposte hanno qualità equivalente;
- `entrambe_inadeguate`: nessuna delle due è accettabile.

Il confronto considera correttezza rispetto alle evidenze, pertinenza,
completezza, tracciabilità delle citazioni e chiarezza. Una parità assegna un
punto a entrambi i sistemi; l'ultima scelta non assegna punti.

```powershell
.\.venv\Scripts\python.exe -m valutazione.genera_grafici
```

Il comando aggiorna in `valutazione/grafici/` il confronto delle metriche,
l'indice finale, la latenza mediana e le evidenze medie. L'indice pesa la
preferenza umana al 40%, l'F1 del recupero al 25%, la copertura delle citazioni
al 15%, le risposte verificabili al 10% e la rapidità relativa al 10%.

## Ricostruzione completa

Questi passaggi servono soltanto dopo un nuovo snapshot o una modifica alla
normalizzazione o alla correlazione.

1. In n8n importare `n8n/workflows/ioc_collection.json`, configurare la
   credenziale OTX ed eseguire manualmente `CTI - Collection e Snapshot`.
2. Eseguire:

```powershell
.\.venv\Scripts\python.exe -m normalizzazione.esegui_normalizzazione
.\.venv\Scripts\python.exe -m grafo_conoscenza.esegui_correlazione
.\.venv\Scripts\python.exe -m grafo_conoscenza.esegui_caricamento
.\.venv\Scripts\python.exe -m grafo_conoscenza.esegui_embedding
.\.venv\Scripts\python.exe -m pytest -q
```

Il caricamento verifica prima tutti i file, quindi sostituisce il contenuto del
grafo. Non interromperlo e non usare `docker compose down -v`, perché `-v`
elimina i dati persistenti di Neo4j e n8n.

## Arresto

Terminare Streamlit con `Ctrl+C`, quindi fermare i contenitori senza cancellare
i volumi:

```powershell
docker compose stop
```

Il prototipo è accademico: gli indicatori riportano osservazioni delle fonti e
non costituiscono da soli una garanzia attuale di malevolenza.
