#!/usr/bin/python3
import nmap
scanner = nmap.PortScanner()
print("Welcome to Simple Nmap Scanning Tool !!")
print("-------------------------------------------------------------------------")
   
ip_addr = input("Please enter the IP Address to Scan: ")
print("The IP entered is:", ip_addr)
print("type of ip_addr:",type(ip_addr))
   
resp = input("""\n Please Enter the type of Scan you want to perform:
    1. SYN Scan
    2. UDP Scan
    3. Comprehensive Scan
    4. TCP Connect Scan
    5. OS Detection Scan
    6. Version Detection Scan
    \n""")
   
print("You have selected:", resp)
resp_dict = {
        '1': ['-sS -sV -sC -O -v', 'tcp'],  # SYN Scan
        '2': ['-sU -sV -v', 'udp'],         # UDP Scan
        '3': ['-sS -sU -sV -sC -O -A -v', 'tcp'],  # Comprehensive Scan
        '4': ['-sT -sV -v', 'tcp'],         # TCP Connect Scan
        '5': ['-O -v', 'tcp'],              # OS Detection Scan
        '6': ['-sV -v', 'tcp']              # Version Detection Scan
    }
   
if resp not in resp_dict.keys():
    print("Please Enter a Valid Option!")
else:
   
    print("Nmap Version:", scanner.nmap_version())
   
    scan_option = resp_dict[resp][0]
    protocol = resp_dict[resp][1]
   
    scanner.scan(ip_addr, "1-1024", scan_option)
   
    if scanner[ip_addr].state() == 'up':
        print("\nHost is up. Scan Results:")
        for proto in scanner[ip_addr].all_protocols():
            print("\nProtocol: {}".format(proto))
            ports = scanner[ip_addr][proto].keys()
            print("Open ports: {}".format(','.join(map(str, scanner[ip_addr][proto].keys()))))
           
            for port in ports:
                info = scanner[ip_addr][proto][port]
                print("\nPort: {}\tService: {}\tState: {}".format(port, info['name'], info['state']))
    else:
        print("Host is down.")

    
print("The process is completed!!")
