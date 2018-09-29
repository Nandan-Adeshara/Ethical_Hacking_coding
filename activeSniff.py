import nmap,os,time
from scapy.all import *
os.system('clear')
print "||WELCOME TO PORTSCANNER||"
print "||----------------------||"
nm = nmap.PortScanner() # object for port scan
time.sleep(3)
print "\nScanned Details-"
# ip = '127.0.0.1-10'
# ip = raw_input("Enter your ip address (write 'ifconfig' in terminal to get ip)")
nm.scan(IP().src,'1-100') # gets src ip and src ports

for host in nm.all_hosts():
		state = nm[host].state()
		print ("Scanned : {} \t State: {}").format(host,state)
		# iterating protocols on host
		for protocol in nm[host].all_protocols():
			port_list = nm[host][protocol].keys()
			#iterating port in a protocol on a host
			for port in port_list:
				#stateof the protcol
				pstate = nm[host][protocol][port]['state']
				#name of the protcol
				pname = nm[host][protocol][port]['name']
				print " |Port:{}|  |State:{}|  |Service:{}|".format(port,pstate,pname)
				print"\n"

''' OUTPUT
|WELCOME TO PORTSCANNER||
||----------------------||

Scanned Details-
Scanned : 127.0.0.1 	 State: up
Port:80	State:open	Service:http

-------
||WELCOME TO PORTSCANNER||
||----------------------||

Scanned Details-
Scanned : 127.0.0.1 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.10 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.2 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.3 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.4 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.5 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.6 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.7 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.8 	 State: up
 |Port:80|  |State:open|  |Service:http|


Scanned : 127.0.0.9 	 State: up
 |Port:80|  |State:open|  |Service:http|

'''