import nmap

print "Welcome to ScanMap by XgavHacker"
print "<-------------------------------------------------------->"
client_choice = raw_input("Enter the IP Address you want to scan: ")

portscanner = nmap.PortScanner()

choose_scan = raw_input("""- Please Choose the type of scan you want to run on your IP Address -
				1) Type '1' to run SYN ACK Scan
				2) Type '2' to run UDP Scan
				3) Type '3' to run Comprehensive Scan\nYour Option is: """)
				
if choose_scan == '1':
	print "The SYN ACK Scan is running ... "
	portscanner.scan(client_choice, '1-1024','-v -sS')
	print "The Host is:",portscanner[client_choice].state()
	print "Open Ports:", portscanner[client_choice]['tcp'].keys()
elif choose_scan == '2':
	print "The UDP Scan is running ..."
	portscanner.scan(client_choice,'1-1024','-v -sU')
	print "The Host is:",portscanner[client_choice].state()
	print "Open Ports:",portscanner[client_choice]['udp'].keys()

elif choose_scan == '3':
	print "The Comprehensive Scan is running ..."
	portscanner.scan(client_choice,'1-1024','-v -sS -sU -sC -A -O')
	print "The Host is:",portscanner[client_choice].state()
	print "Open Ports:",portscanner[client_choice]['tcp'].keys()
else:
	print "Please enter a Valid Option!"
	
							
