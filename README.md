# multi-threaded_UDP_port_scanner

This code is a multi-threaded UDP port scanner written in Python, which analyzes a target host to identify open ports and active services using specific payloads for various services.
https://www.aiutocomputerhelp.it/python-scansione-puntuale-delle-porte-udp-concetto-di-payload/

How the Software Works
Uses the socket module to send UDP packets to a host and check for responses.
Logs results in a file called risultati_scansione_ScanUDP.txt.
Utilizes simultaneous threads (ThreadPoolExecutor) to perform parallel scans over a wide range of ports, improving efficiency.

Sends specific payloads to detect UDP services such as:

DNS (port 53)
SNMP (port 161)
NTP (port 123)
NetBIOS (port 137)
RIP (port 520)
TFTP (port 69)
Syslog (port 514)
DHCP (ports 67 and 68)
RADIUS (port 1812)
IKE (IPsec VPN) (port 500)
mDNS (port 5353)
SSDP (port 1900)
SQL Server Browser (port 1434)
Possible backdoors or trojans (port 9999)
Includes a function to send fake probes on non-standard ports, attempting to identify services that respond to anomalous payloads.
Software Objectives
Identify open UDP ports on a target IP.
Detect exposed services by sending specific payloads.
Scan up to 65,535 ports, an operation that may take a long time.
Automate the scanning process using multithreading to improve speed.
Possible Uses
Security auditing to check which services are exposed on a network.
Testing private networks to verify misconfigurations.
Detecting hidden services or active backdoors in a system.

Disclaimer

This software is provided solely for educational and security auditing purposes. It is intended to help network administrators, security professionals, and researchers identify vulnerabilities and improve the security of their own systems.

Unauthorized use of this software on networks or systems without explicit permission from the owner is strictly prohibited. Scanning or probing networks without consent may violate local laws, regulations, and organizational policies. The author and distributor of this software assume no liability for any misuse, legal consequences, or damages resulting from its use.

By using this software, you acknowledge that:

You have obtained explicit authorization to test the target systems.
You take full responsibility for your actions and any consequences arising from them.
You comply with all applicable laws, regulations, and ethical guidelines regarding cybersecurity testing.
If you are unsure about the legality of your actions, do not use this software. Always ensure compliance with ethical hacking standards and responsible disclosure practices.
