# -------------------------------------------------------------------------
# Aiutocomputerhalp.it - autore: Giovanni Popolizio
# mail: aiuto.computerhelp@gmail.com
# Programma di libero utilizzo e distribuzione.
# Link: https://www.aiutocomputerhelp.it/python-scansione-puntuale-delle-porte-udp-concetto-di-payload/
# Versione 1.0 - Servizi ricercati su porte con protocoolo UDP
# Ricordate sempre: i servizi esposti non sempre si trovano sulle porte canoniche.
# Quindi se ritrovate le porte riconducibili a questi servizi con sollecitazioni mirate , di sicuro i servizi esposti sono quelli.
# Software: SoloUDP_1.py 
#  Attenzione  fare la ricerca su 65535 porte significa fare 65535 X 15
# per un totale di  983025 Test. Potreste aspettare anche giorni !!
# ---------------------------------------------------------------------------

import socket
import paramiko
import sys
import logging
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configura il logging di paramiko per mostrare solo errori critici
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

# Funzione per leggere il file di log
def read_log_file():
    try:
        with open("risultati_scansione_ScanUDP.txt", "r") as file:
            print("\n--- Log dei risultati della scansione www.aiutocomputerhelp.it 2024---")
            print(file.read())
    except FileNotFoundError:
        print("Il file di log non è stato trovato. Nessun risultato da mostrare.")

# Funzione per salvare i risultati nel file di log UDP
def log_result_udp(ip, port, description=""): 
    with open("risultati_scansione_ScanUDP.txt", "a") as file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - IP/Host: {ip}, Porta UDP trovata: {port}"
        if description:
            log_message += f" - Descrizione del servizio: {description}"
        log_message += "\n"
        file.write(log_message)
        print(f"Risultato registrato nel file per l'IP {ip}, porta {port}")

# Funzione per salvare i risultati nel file di log UDP per i Fake
def log_result_udp_fake(ip, port, description="" , Probe="" ): 
    with open("risultati_scansione_ScanUDP.txt", "a") as file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - IP/Host: {ip}, Porta UDP trovata: {port}"
        if description:
            log_message += f" - Associato al  probe {Probe} : {description}"
        log_message += "\n"
        file.write(log_message)
        print(f"Risultato registrato nel file per l'IP {ip}, porta {port}")        

def check_service_udp(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        description = ""

        # Invia un messaggio specifico in base alla porta
        if port == 53:
            message = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'  # DNS query
            description = "DNS (Domain Name System)"
        elif port == 161:
            message = b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'  # SNMP
            description = "SNMP (Simple Network Management Protocol)"
        elif port == 123:
            message = b'\x1b' + 47 * b'\x00'  # NTP request
            description = "NTP (Network Time Protocol)"
        elif port == 137:
            message = b'\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'  # NetBIOS
            description = "NetBIOS Name Service"
        elif port == 520:
            message = b'\x01\x02\x00\x00' + 20 * b'\x00'  # RIP request
            description = "RIP (Routing Information Protocol)"
        elif port == 69:
            message = b'\x00\x01' + b'pippo.txt\x00' + b'octet\x00'  # TFTP RRQ
            description = "TFTP (Trivial File Transfer Protocol)"
        elif port == 514:
            message = b'<34>1 2024-11-11T23:45:00Z hostname appname - - - Test log message'  # Syslog
            description = "Syslog"
        elif port == 67 or port == 68:
            message = b'\x01\x01\x06\x00' + 28 * b'\x00'  # DHCP Discover (semplificato)
            description = "DHCP (Dynamic Host Configuration Protocol)"
        elif port == 1812:
            message = b'\x01\x01\x00\x14' + 16 * b'\x00'  # Messaggio di autenticazione RADIUS
            description = "RADIUS (Remote Authentication Dial-In User Service)"
        elif port == 500:
            message = b'\x00\x00\x00\x00' + 12 * b'\x00'  # Payload generico IKE
            description = "IKE (Internet Key Exchange)"
        elif port == 1900:
            message = b'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:1\r\nST:ssdp:all\r\n\r\n'
            description = "SSDP (Simple Service Discovery Protocol)"
        elif port == 1434:
            message = b'\x02'  # Richiesta per SQL Server Browser
            description = "SQL Server Browser Service"
        elif port == 4500:
            message = b'\x00\x00\x00\x00' + 12 * b'\x00'  # Payload generico per NAT-T
            description = "NAT Traversal (IPsec VPN)"
        elif port == 5353:
            message = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01'
            description = "mDNS (Multicast DNS)"
        elif port == 9999:
            message = b'ping'
            description = "Possibile backdoor o trojan (porta 9999)"
        else:
            message = b'\x00'  # Messaggio vuoto per le altre porte

        sock.sendto(message, (ip, port))

        try:
            data, _ = sock.recvfrom(1024)
            if data:
                print(f"Porta {port} aperta (UDP)")
                log_result_udp(ip, port, description)
                return True
        except socket.timeout:
            print(f"Porta UDP {port} chiusa o nessuna risposta ")
        except OSError as e:
            print(f"Errore di sistema su porta UDP {port}: {e}")
    except socket.error as e:
        print(f"Errore di rete su porta UDP {port}: {e}")
    finally:
        sock.close()
    return False

def check_service_udp_fake(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        responses = {}

        # Probes per diversi servizi
        probes = {
            53: (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07aiutocomputerhelp\x03it\x00\x00\x01\x00\x01', "DNS (Domain Name System)"),
            161: (b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00', "SNMP (Simple Network Management Protocol)"),
            123: (b'\x1b' + 47 * b'\x00', "NTP (Network Time Protocol)"),
            137: (b'\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01', f"NetBIOS Name Service (porta {port})"),
            520: (b'\x01\x02\x00\x00' + 20 * b'\x00', "RIP (Routing Information Protocol)"),
            69: (b'\x00\x01' + b'pippo.txt\x00' + b'octet\x00', "TFTP (Trivial File Transfer Protocol)"),
            514: (b'<34>1 2024-11-11T23:45:00Z hostname appname - - - Test log message', "Syslog"),
            67: (b'\x01\x01\x06\x00' + 28 * b'\x00', "DHCP (Dynamic Host Configuration Protocol)"),
            1812: (b'\x01\x01\x00\x14' + 16 * b'\x00', "RADIUS (Remote Authentication Dial-In User Service)"),
            500: (b'\x00\x00\x00\x00' + 12 * b'\x00', "IKE (Internet Key Exchange)"),
            1900: (b'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:1\r\nST:ssdp:all\r\n\r\n', "SSDP (Simple Service Discovery Protocol)"),
            1434: (b'\x02', "SQL Server Browser Service"),
            4500: (b'\x00\x00\x00\x00' + 12 * b'\x00', "NAT Traversal (IPsec VPN)"),
            5353: (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01', "mDNS (Multicast DNS)"),
            9999: (b'ping', "Possibile backdoor o trojan (porta 9999)")
        }

        # Invia ogni probe per vedere quale risposta viene ricevuta
        for probe_port, (message, description) in probes.items():
            print(f"Testando i probe sulla porta {port}\n ")
            try:
                sock.sendto(message, (ip, port))
                data, _ = sock.recvfrom(1024)
                if data:
                    responses[port] = description
                    log_result_udp_fake(ip, port, description, probe_port)
                    print(f"Porta {port} risponde al probe del servizio  {description}")
                    return True
            except socket.timeout:
                continue
            except OSError as e:
                print(f"Errore di sistema su porta UDP {port} durante probe {description}: {e}")
    except socket.error as e:
        print(f"Errore di rete su porta UDP {port}: {e}")
    finally:
        sock.close()
    return False

# Funzione principale per gestire la scansione di range di porte con multithreading
def scan_ports(ip, range1, range2=None, range3=None):

    ###########################################################
    max_threads = 40  # Numero massimo di thread simultanei
    #potete modificare questo numero in base alla velocità di
    #risposta e potenza del vs client
    ###########################################################
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []

         #Aggiungi i compiti di scansione UDP per ogni porta nelle futures
        for port in range1:
            futures.append(executor.submit(check_service_udp, ip, port))
        if range2:
            for port in range2:
                futures.append(executor.submit(check_service_udp, ip, port))
        if range3:
            for port in range3:
                futures.append(executor.submit(check_service_udp, ip, port))

         #Gestisci i risultati man mano che i thread terminano
        for future in as_completed(futures):
            future.result()  

    # Effettua la scansione con check_service_udp_fake per trovare servizi su porte non canoniche
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []

        for port in range1:
            futures.append(executor.submit(check_service_udp_fake, ip, port))
        if range2:
            for port in range2:
                futures.append(executor.submit(check_service_udp_fake, ip, port))
        if range3:
            for port in range3:
                futures.append(executor.submit(check_service_udp_fake, ip, port))

        # Gestisci i risultati man mano che i thread terminano
        for future in as_completed(futures):
            future.result()  # 

    # Lettura del file di log al termine della scansione
    read_log_file()

######################################################################################################
#----------------------------------------------------------------------------------------------------#

# Esempio di utilizzo
target_ip = "192.168.1.128"  # Sostituisci con l'indirizzo IP target o nome host

range1 = range(1, 10000)        # Potete aggiungere quanti range di porte volete
range2 = range(1, 1)      # dovete modificare anche _ports(ip, range1, range2=None , range3=Nome) etc etc
range3 = range(1, 1)      # dovete modificare anche _ports(ip, range1, range2=None , range3=Nome) etc etc

scan_ports(target_ip, range1, range2, range3)
