import subprocess 
import re 
import sys 
import csv 
import json
from datetime import datetime
import time


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


if len(sys.argv) != 3:
    print(f"{RED}Usage: python3 host_scaning.py <port> <target hosts>")
    print(f"{RESET}Example: python3 host_scaning.py 21,80 192.168.37.129,192.168.37.130")
    sys.exit()

port = sys.argv[1]
hosts = sys.argv[2].split(",")

print(f"{YELLOW}=============Scanning Hosts......=================")

json_data = []
csv_rows = []

for host in hosts:
    command = ["nmap", "-sT", "-sV", "-O", "-p", port,host]
    result = subprocess.run(command, capture_output=True, text=True)
    scanning_time = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    print(f"{'-'*60}\n")
    print(f"{GREEN}Target: {host}")
    print(f"{'-'*60}\n")

    
    host_info = {
        "host": host,
        "scanning_time": scanning_time,
        "ports": [],
        "os": None,
        "mac": None,
        "os_details": None
    }

    # Port scanning
    for line in result.stdout.split("\n"):
        port_matches = re.finditer(r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)", line)
        for port_match in port_matches:
            port = port_match.group(1)
            protocole = port_match.group(2)
            state = port_match.group(3)
            service = port_match.group(4)
            version = port_match.group(5)

            port_info = {
                "port": port,
                "protocole": protocole,
                "state": state,
                "service": service,
                "version": version
            }
            host_info["ports"].append(port_info)

            csv_rows.append([host, port, protocole, state, service, version])

            # Print status
            if state == "open":
                # print(f"Target: {host}")
                # print(f"{'-'*60}\n")
                print(f"{GREEN} {port} is open")
                print(f"{YELLOW}Wait a some moment... ")
                time.sleep(1)
                print(f"{CYAN}Port: {port}")
                print(f"Protocol: {protocole}")
                print(f"STATE: {state}")
                print(f"SERVICE: {service}")
                print(f"VERSION: {version}")
            elif state == "filtered":
                # print(f"{GREEN}Target: {host}\n")
                # print(f"{'-'*60}\n")
                print(f"{RED}Maybe firewall is on. Try various scan types")
                
                print(f"{YELLOW}Wait a some moment... ")
                time.sleep(1)
                print(f"{CYAN}Port: {port}")
                print(f"Protocol: {protocole}")
                print(f"STATE: {state}")
                print(f"SERVICE: {service}")
                print(f"VERSION: {version}")
            else:
                # print(f"{GREEN}Target: {host}")
                # print(f"{'-'*60}\n")
                print(f"{RED} {port} No. port not open")
                print(f"{YELLOW}Wait a some moment... ")
                time.sleep(1)
                print(f"{CYAN}Port: {port}")
                print(f"Protocol: {protocole}")
                print(f"STATE: {state}")
                print(f"SERVICE: {service}")
                print(f"VERSION: {version}")

    # MAC Address
    mac_addr_match = re.search(r"MAC Address: (([A-F0-9a-f]{2}:){5}[A-F0-9a-f]{2})\s*\(VMware\)", result.stdout)
    if mac_addr_match:
        host_info['mac'] = mac_addr_match.group(1)
        print(f"MAC Address: {mac_addr_match.group(1)}")
    else:
        print('<MAC Address not found>')

    # OS
    os_match = re.search(r"Running:\s+(\w+)\s+([0-9A-Za-z-](\.[0-9A-Za-z-]+)+)", result.stdout)
    if os_match:
        host_info['os'] = f"{os_match.group(1)}, {os_match.group(2)}"
        print(f"Operating System: {os_match.group(1)} {os_match.group(2)}")
    else:
        print("OS information not found")

    # OS details
    os_details_match = re.search(r"OS details:\s+(\w+)\s+([0-9A-Za-z-](\.[0-9A-Za-z-]+)+)", result.stdout)
    if os_details_match:
        host_info["os_details"] = f"{os_details_match.group(1)} {os_details_match.group(2)}"
        print(f"OS Details: {os_details_match.group(1)} {os_details_match.group(2)}")
    else:
        print("No OS Details Found\n")

    # Append host info always
    json_data.append(host_info)

# ------ TXT Report --------
with open('host_scaning_report.txt','w') as txt:
    txt.write(f"{GREEN}===========Scanning Report===========\n")
    txt.write(f"Scanning Date: {scanning_time}\n\n")
    
    for host in json_data:
        txt.write(f"{GREEN}Target Host: {host['host']}\n")
        if host['ports']:
            for p in host['ports']:
                txt.write(
                    f"Port: {p['port']} | "
                    f"Protocol: {p['protocole']} | "
                    f"State: {p['state']} | "
                    f"Service: {p['service']} | "
                    f"Version: {p['version']}\n"
                )
        else:
            txt.write("No port information found\n")

        txt.write(f"OS: {host['os']}\n")
        txt.write(f"MAC Address: {host['mac']}\n")
        txt.write(f"OS Details: {host['os_details']}\n\n")

# ------ CSV Report --------
with open('host_scaning_report.csv','w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Host','Port','Protocol','State','Service','Version'])
    writer.writerows(csv_rows)

# ------ JSON Report --------
with open("host_scaning_report.json", "w") as jsonfile:
    json.dump(json_data, jsonfile, indent=4)

# ----------- Final Output ----------------
print(f"{CYAN}=================Scan Complete===============")
print(f"Generated Reports:")
print("- host_scaning_report.txt")
print("- host_scaning_report.csv")
print("- host_scaning_report.json")