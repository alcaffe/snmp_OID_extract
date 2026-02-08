
# Estrazione OID da HTTP POST /Snmp.Set

Questo repository contiene uno script Python che consente di analizzare file PCAP/PCAPNG e
estrarre automaticamente coppie OID/Valore presenti nei body JSON delle richieste:

```
HTTP POST /Snmp.Set
```

## Funzionalità principali
- GUI basata su **Tkinter** per selezione file e inserimento parametri.
- Parsing dei pacchetti con **PyShark**.
- Ricostruzione automatica dei body HTTP.
- Filtraggio dinamico per IP di destinazione.
- Estrazione coppie OID/Valore dal JSON.
- Generazione file di output configurabile.

## Requisiti
- Python 3.8+
- Tshark installato e accessibile nel PATH.
- I moduli Python elencati in `requirements.txt`.

## Installazione
```
pip install -r requirements.txt
```

Assicurarsi che **tshark** sia installato:
- Ubuntu/Debian: `sudo apt install tshark`
- Windows: installare da https://www.wireshark.org

## Esecuzione
Apri wireshark e utilizza il browser per configurare il device.
Terminate le operazioni salva il file. Ora puoi usare lo script.
```
python estrai_snmpset_http.py
```
Si aprirà automaticamente l'interfaccia grafica per:
1. Selezionare il file PCAP.
2. Scegliere percorso del file di output.
3. Inserire più volte (se necessario) coppie IP/Host.

## Autore
M. Fumagalli
