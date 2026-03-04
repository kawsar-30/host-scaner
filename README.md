🚀 HOST SCANNING AUTOMATION TOOL
📌 PROJECT DESCRIPTION

Host Scanning Automation Tool is a cybersecurity practice project developed using Python for automating network reconnaissance tasks.

This project integrates Python scripting with Nmap to perform structured host and port scanning operations. It is designed as a practical implementation of foundational network security concepts.

The objective of this project is to demonstrate:

Network scanning techniques

Service and version detection

Operating System fingerprinting

MAC address extraction

Command-line argument processing

Output parsing using regular expressions

Multi-format report generation (TXT, CSV, JSON)

🎯 PROJECT PURPOSE

This project was developed for:

Cybersecurity learning

Lab-based penetration testing practice

Strengthening Python automation skills

Building portfolio-ready security tools

🚀 USAGE INSTRUCTIONS
Command Format
python3 host_scaning.py <port_list> <target_ip_list>
Example
python3 host_scaning.py 21,80 192.168.37.129,192.168.37.130
⚙️ PARAMETERS

<port_list>
Comma-separated list of ports to scan.

<target_ip_list>
Comma-separated list of target IPv4 addresses.

📊 PROJECT FUNCTIONALITY

For each target, the project executes:

nmap -sT -sV -O -p <port_list> <target_ip>

The project extracts:

Port state (open, closed, filtered)

Service name and version

Operating system information

OS detailed fingerprint

MAC address (if available)

Timestamped scan record

📂 GENERATED OUTPUT

The project automatically generates:

host_scaning_report.txt

host_scaning_report.csv

host_scaning_report.json

⚠️ ETHICAL & LEGAL NOTICE

This project is intended strictly for educational and authorized testing purposes.
Unauthorized scanning of systems without explicit permission may violate laws and regulations.
