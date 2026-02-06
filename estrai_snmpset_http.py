
import json
import sys
import traceback
import ipaddress
import re
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from datetime import datetime

# PyShark richiede tshark installato e raggiungibile nel PATH
try:
    import pyshark
except ImportError:
    print("Errore: 'pyshark' non è installato. Esegui: pip install pyshark")
    sys.exit(1)

APP_TITLE = "Estrazione OID da HTTP POST /Snmp.Set"
AUTHOR = "M. Fumagalli"

# =========================
# Utilità protocollo/parse
# =========================
def estrai_body_http(pkt):
    """
    Estrae il body HTTP (http.file_data) come stringa UTF-8 (ignora errori).
    Ritorna None se non disponibile.
    """
    try:
        if hasattr(pkt, 'http') and hasattr(pkt.http, 'file_data'):
            fd = pkt.http.file_data
            # Alcune versioni di pyshark offrono .binary_value
            try:
                data = fd.binary_value
                if isinstance(data, (bytes, bytearray)):
                    return data.decode('utf-8', errors='ignore')
            except Exception:
                pass
            # Fallback: come stringa generica
            return str(fd)
    except Exception:
        # Non bloccare l'intero parsing su un pacchetto buggato
        return None
    return None

def parse_json_body_for_oids_and_values(body_text):
    """
    Parse del JSON nel body. Estrae:
      - 'o' = lista OID (stringhe)
      - 'v' = lista valori (convertiti a stringa)
    Ritorna lista di tuple (oid, val) accoppiate per indice.
    """
    try:
        obj = json.loads(body_text)
    except json.JSONDecodeError:
        return []

    o_list = obj.get("o")
    v_list = obj.get("v")

    if not isinstance(o_list, list) or not isinstance(v_list, list):
        return []

    pairs = []
    for i in range(min(len(o_list), len(v_list))):
        oid = str(o_list[i]) if o_list[i] is not None else ""
        val = str(v_list[i]) if v_list[i] is not None else ""
        pairs.append((oid, val))
    return pairs

def build_display_filter(dst_ip: str) -> str:
    """
    Crea il display filter Wireshark dinamico per PyShark.
    Esempio:
    http.request.method == "POST" && ip.dst == 10.27.4.47 && http.request.uri contains "/Snmp.Set"
    """
    return (
        f'http.request.method == "POST" && '
        f'ip.dst == {dst_ip} && '
        f'http.request.uri contains "/Snmp.Set"'
    )

# =========================
# I/O su file
# =========================
def init_output_file(output_path: str, pcap_path: str):
    """Scrive l'intestazione generale del file di output (una sola volta)."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# File CFG generato automaticamente\n")
        f.write(f"# Origine: HTTP POST /Snmp.Set\n")
        f.write(f"# PCAP: {pcap_path}\n")
        f.write(f"# Autore: {AUTHOR}\n")
        f.write(f"# Generato: {datetime.now().isoformat()}\n")
        f.write("# ------------------------------------------------------------\n\n")

def append_section_header(output_path: str, dst_ip: str, host_name: str, display_filter: str):
    """Aggiunge una intestazione di sezione per una specifica combinazione IP/Host."""
    with open(output_path, 'a', encoding='utf-8') as f:
        f.write(f"## Sezione - Destinazione: {dst_ip} | Host: {host_name}\n")
        f.write(f"# Filtro: {display_filter}\n\n")

def append_snmp_set_lines(output_path: str, host_name: str, pairs):
    """
    Appende le righe SNMP:Set per le coppie (oid, val).
    Esempio:
      SNMP:Set(host=EQP_LOC, oidName=Tobedeclare, oid=1.3..., value=2, snmpType=INTEGER);
    """
    with open(output_path, 'a', encoding='utf-8') as f:
        for (oid, val) in pairs:
            f.write(
                f"SNMP:Set(host={host_name}, oidName=Tobedeclare, oid={oid}, value={val}, snmpType=INTEGER);\n"
            )
        f.write("\n")

# =========================
# Elaborazione principale
# =========================
def run_extraction(pcap_path: str, output_path: str, dst_ip: str, host_name: str):
    """
    Apre il PCAP con il display filter, estrae OID/valori dal JSON del body
    e appende le righe SNMP:Set al file di output sotto la sezione corrente.
    Ritorna (packets_count, pairs_count).
    """
    display_filter = build_display_filter(dst_ip)

    # Preferenze per aiutare il riassemblaggio del body HTTP
    override_prefs = {
        'tcp.desegment_tcp_streams': 'true',
        'http.desegment_body': 'true',
        # Se il body risultasse compresso (poco comune nelle request), abilita:
        # 'http.decompress_body': 'true',
    }

    # Aggiungi l'intestazione di sezione
    append_section_header(output_path, dst_ip, host_name, display_filter)

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=display_filter,
        keep_packets=False,
        override_prefs=override_prefs,
    )

    total_packets = 0
    total_pairs = 0

    try:
        for pkt in cap:
            total_packets += 1
            body = estrai_body_http(pkt)
            if not body:
                continue

            pairs = parse_json_body_for_oids_and_values(body)
            if not pairs:
                continue

            append_snmp_set_lines(output_path, host_name, pairs)
            total_pairs += len(pairs)
    finally:
        cap.close()

    return total_packets, total_pairs

# =========================
# GUI (Tkinter)
# =========================
def chiedi_ip() -> str | None:
    dst_ip = simpledialog.askstring(APP_TITLE, "Inserisci l'IP di destinazione (ip.dst):")
    if not dst_ip:
        return None
    try:
        ipaddress.IPv4Address(dst_ip)
    except Exception:
        messagebox.showerror(APP_TITLE, f"Indirizzo IP non valido: {dst_ip}")
        return None
    return dst_ip

def chiedi_host() -> str | None:
    host_name = simpledialog.askstring(APP_TITLE, "Inserisci il nome host (es. EQP_LOC):")
    if not host_name:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._-]+", host_name):
        messagebox.showerror(APP_TITLE, "Nome host non valido. Usa solo lettere, numeri, punto (.), underscore (_) e trattino (-).")
        return None
    return host_name

def main_gui():
    root = tk.Tk()
    root.withdraw()
    root.update()

    # 1) Selezione PCAP/PCAPNG
    pcap_path = filedialog.askopenfilename(
        title="Seleziona file PCAP/PCAPNG",
        filetypes=[("PCAP/PCAPNG", "*.pcap *.pcapng *.cap"), ("Tutti i file", "*.*")]
    )
    if not pcap_path:
        messagebox.showinfo(APP_TITLE, "Operazione annullata (nessun file selezionato).")
        return

    # 2) Scelta file di output
    default_out = pcap_path.rsplit('.', 1)[0] + "_snmpset_extract.cfg"
    output_path = filedialog.asksaveasfilename(
        title="Scegli dove salvare il file",
        initialfile=default_out,
        defaultextension=".cfg",
        filetypes=[("All types", "*.*")]
    )
    if not output_path:
        messagebox.showinfo(APP_TITLE, "Operazione annullata (nessun percorso di salvataggio selezionato).")
        return

    # 3) Intestazione generale del file
    init_output_file(output_path, pcap_path)

    # 4) Ciclo principale: IP/Host -> Estrazione -> Chiedi se continuare
    session_total_packets = 0
    session_total_pairs = 0
    step = 1
    while True:
        # Chiedi IP
        dst_ip = chiedi_ip()
        if dst_ip is None:
            # Niente IP: chiedi se vuoi terminare
            if not messagebox.askyesno(APP_TITLE, "Nessun IP inserito.\nVuoi inserire un altro IP/host?\nSì = continua | No = esci"):
                break
            else:
                continue

        # Chiedi host
        host_name = chiedi_host()
        if host_name is None:
            # Niente host: chiedi se vuoi terminare
            if not messagebox.askyesno(APP_TITLE, "Nessun host inserito.\nVuoi inserire un altro IP/host?\nSì = continua | No = esci"):
                break
            else:
                continue

        # Esecuzione estrazione
        try:
            packets, pairs = run_extraction(pcap_path, output_path, dst_ip, host_name)
            session_total_packets += packets
            session_total_pairs += pairs

            messagebox.showinfo(
                APP_TITLE,
                f"[Esecuzione #{step}] Completato.\n"
                f"Pacchetti HTTP POST /Snmp.Set analizzati (per questo filtro): {packets}\n"
                f"Coppie OID/Valore estratte (per questo filtro): {pairs}\n\n"
                f"Output aggiornato in:\n{output_path}"
            )
            step += 1
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror(APP_TITLE, f"Errore durante l'elaborazione:\n{e}")
            # In caso di errore, chiedi se continuare o uscire
            if not messagebox.askyesno(APP_TITLE, "Vuoi provare ad inserire un altro IP/host?\nSì = continua | No = esci"):
                break

        # Chiedi se continuare con un altro IP/host o terminare
        if not messagebox.askyesno(APP_TITLE, "Vuoi filtrare un ulteriore indirizzo IP e inserire un altro host?\nSì = continua | No = termina ed esci"):
            break

    # 5) Riepilogo sessione
    messagebox.showinfo(
        APP_TITLE,
        f"Sessione terminata.\n"
        f"Totale pacchetti analizzati: {session_total_packets}\n"
        f"Totale coppie OID/Valore estratte: {session_total_pairs}\n\n"
        f"File salvato in:\n{output_path}"
    )

if __name__ == "__main__":
    main_gui()
