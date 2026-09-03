# Protocollo di valutazione

`casi.jsonl` contiene 70 domande annotate prima di eseguire l'esperimento:

- 20 casi centrati sugli indicatori;
- 20 casi centrati su malware e software;
- 20 casi centrati su attori e tecniche;
- 10 casi trasversali che richiedono due o tre domini.

Ogni riga dichiara la domanda italiana, i domini attesi e le entita di
riferimento che il recupero deve rendere disponibili. Le 87 entita attese sono
state ricontrollate sullo snapshot verificato: ciascuna esiste una sola volta,
ha provenienza e copre tutti i domini dichiarati dal caso. I casi sugli IOC
contengono necessariamente il valore esatto: per scelta metodologica hash,
indirizzi e URL non hanno ricerca semantica.

L'esperimento si avvia dalla radice del progetto con:

```powershell
python -m valutazione.esegui
```

Lo script riscalda una volta il sistema, alterna quale configurazione parte per
prima e scrive progressivamente `risultati.jsonl`. Al termine produce
`valutazione_deterministica.json`. Per evitare di sovrascrivere una misura gia
conclusa, i file esistenti vanno rimossi esplicitamente con l'opzione
`--sovrascrivi`.

Le misure usate nel confronto sono:

- F1 del recupero sui riferimenti attesi;
- copertura dei riferimenti attesi nelle citazioni;
- quota di risposte con almeno una citazione verificabile;
- latenza mediana;
- preferenza umana comparativa;
- numero medio di evidenze recuperate, mantenuto come dato descrittivo e non
  incluso nell'indice finale.

Accuratezza esatta e macro-F1 multilabel restano nel riepilogo come controllo
specifico del router, non come ulteriori metriche di confronto fra le risposte.

Precisione e richiamo sono calcolati separatamente per ogni domanda e poi
mediati. Indicando con $A_i$ i riferimenti attesi e con $E_i$ le evidenze
recuperate per il caso $i$:

```text
precisione_i = |A_i intersezione E_i| / |E_i|
richiamo_i   = |A_i intersezione E_i| / |A_i|
```

La prima misura e quindi una precisione rispetto ai riferimenti annotati, non
la classificazione semantica di ogni altra evidenza come irrilevante.
Precisione e richiamo confluiscono nell'F1 calcolato per ciascuna domanda e poi
mediato. La copertura delle citazioni e invece micro-aggregata: riferimenti
attesi citati diviso gli 87 riferimenti attesi complessivi.

La validita strutturale di una citazione prova che la chiave citata era presente
nelle evidenze o negli estremi dei loro archi. Non sostituisce un giudizio umano
sulla correttezza semantica di ogni frase, limite dichiarato nella tesi.

## Valutazione umana comparativa

`valutazione_umana.csv` contiene domanda e quattro colonne mutuamente
esclusive. In ogni riga deve comparire un solo `1`; lo script verifica anche che
identificativo e testo coincidano con `casi.jsonl`:

- `router`: la risposta instradata e complessivamente migliore;
- `generale`: la risposta generale e complessivamente migliore;
- `parita`: le risposte hanno qualita equivalente e ricevono entrambe un punto;
- `entrambe_inadeguate`: nessuna risposta riceve un punto.

Il giudizio considera correttezza rispetto alle evidenze, pertinenza,
completezza, tracciabilita delle citazioni e chiarezza. Le scelte presenti sono
preliminari e devono essere confermate manualmente dall'autore.

## Grafici e indice finale

L'indice combina cinque componenti normalizzate: preferenza umana 40%, F1 del
recupero 25%, copertura dei riferimenti citati 15%, risposte con citazione
verificabile 10% e rapidita relativa 10%. La rapidita e il rapporto fra la
latenza mediana migliore e quella della configurazione. Le evidenze medie non
entrano nell'indice: un contesto piu piccolo e utile soltanto se conserva le
informazioni necessarie. Il risultato e un indice sintetico di confronto, non
una probabilita statistica di correttezza.

Dalla radice del progetto eseguire:

```powershell
python -m valutazione.genera_grafici
```

Il comando valida la tabella e genera quattro PNG in `valutazione/grafici/`: confronto
delle tre misure automatiche di qualita con la preferenza umana, indice finale,
tempo mediano ed evidenze medie. Le figure usano soltanto bianco e nero.
