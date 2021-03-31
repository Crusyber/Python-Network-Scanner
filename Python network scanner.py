
import nmap
from netaddr import IPNetwork
from dns.resolver import Resolver

# instantiating the PortScanner
scanner = nmap.PortScanner()

# banner
print("Welcome to my network scanner!")
print("")
print("├┬┬┴┬┴┬┬┴┬┴┬┬┴┬┴┬┬┴┬┴┬┬┴┬┴┬┴┬┴┤ ͜ʖ ͡°)├┬┬┬┴┬┴┬┬┴┬┴┬┬┴┬┴┬┬┴┬┴┬┬┴┬┴┬┬┴┬┴┤")
print("")
##################################################################################

# take input from user
ip_address = input("Please begin by entering the IP address you would like to scan: ")
print("The selected IP address is", ip_address)


# Convert subnet into list of host IPs ( network and broadcast address will excluded )
host_ips = []
for n in IPNetwork(ip_address).iter_hosts():
    # appending each host IP into list
    host_ips.append(str(n))


# Resolving each IP to domain names
for ip_address in host_ips:
    # IP for name server
    ns = ['8.8.8.8']
    # instantiate the resolver
    resolver = Resolver()
    resolver.nameservers = ns
    try:
        # resolve the ip address and parse the output
        print((resolver.resolve_address(ip_address)).response.answer[0])
    except:
        pass


# take input from user about scan type
response = input("""\nSelect the type of scan you would like to run
1)SYN ACK Scan
2)UDP Scan
3)Complete Scan
Option: """)
print("You would like to perform option:", response ,"\n")


if response == '1':
    # looping through each IP and performing a TCP scan (-sS connect scan)
    for ip_address in host_ips:
        print(f"########### {ip_address} ############")
        output = scanner.scan(ip_address, '1-1024', '-sS -v')
        # printing the state of the host ( up/down )
        print("Host is "+ output['scan'][ip_address]['status']['state'])

        try:    
            # access tcp key from the scan object and loop over each scanned port to see if it is open or not
            for port in output['scan'][ip_address]['tcp']:
                if output['scan'][ip_address]['tcp'][port]['state'] == 'open':
                    # if port is open then print to the terminal
                    print(f"Open Port: {port} - {output['scan'][ip_address]['tcp'][port]['name']}")
        except KeyError:
            pass


elif response == '2':
    # looping through each IP and performing a UDP scan (-sU)
    for ip_address in host_ips:
        print(f"########### {ip_address} ############")
        output = scanner.scan(ip_address, '53', '-sU -v')
        print("Host is "+ output['scan'][ip_address]['status']['state'])
        try:
            for port in output['scan'][ip_address]['udp']:
                if output['scan'][ip_address]['udp'][port]['state'] == 'open' or output['scan'][ip_address]['udp'][port]['state'] == 'open|filtered':
                    print(f"Open Port: {port} - {output['scan'][ip_address]['udp'][port]['name']}")
        except KeyError:
            pass


elif response == '3':
    for ip_address in host_ips:
        print(f"########### {ip_address} ############")
        output = scanner.scan(ip_address, '1024', '-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"')
        print("Host is "+ output['scan'][ip_address]['status']['state'])
        try:
            for port in output['scan'][ip_address]['udp']:
                if output['scan'][ip_address]['udp'][port]['state'] == 'open' or output['scan'][ip_address]['udp'][port]['state'] == 'open|filtered':
                    print(f"Open UDP Port: {port} - {output['scan'][ip_address]['udp'][port]['name']}")
        except KeyError:
            pass

        try:
            for port in output['scan'][ip_address]['tcp']:
                    if output['scan'][ip_address]['tcp'][port]['state'] == 'open':
                        print(f"Open TCP Port: {port} - {output['scan'][ip_address]['tcp'][port]['name']}")
        except KeyError:
            pass

elif response >= '4':
    print("Select a valid option")

