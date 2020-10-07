# UnauthenticatedEnum
My solution to the unauthenticated host enumeration home assignment

Requirements
============

 * Python 3
 * A recent release of Impacket.
 * requests
 
 How to use
 ============
 ```
usage: Unauthenticated_Enumeration.py [-h] ip

Enunmerate hosts without authenticating.

positional arguments:
  ip          Address or address range to scan, netmask required for address range (examples: single ip - 10.1.1.12 , class c semgment - 10.1.1.0/24)
              (address range might be slow)

optional arguments:
  -h, --help  show this help message and exit
 ```
 
 Example
 ===========
 ```
 kali@kali:~/Desktop$ python3 ./Unauthenticated_Enumeration.py 192.168.80.131
192.168.80.131 is up. Enumerating...
SMB
NetBIOS computer name: WIN-T3IGV8F2SF0
NetBIOS domain name (Computer name if not domain joined): WIN-T3IGV8F2SF0
Domain FQDN (Computer name if not domain joined): WIN-T3IGV8F2SF0
Computer FQDN: WIN-T3IGV8F2SF0
Computer os version: 6.3
Computer os build: 9600
Computer is a server
RPC
Computer is x64
NetBIOS computer name: WIN-T3IGV8F2SF0
NetBIOS domain name (Computer name if not domain joined): WIN-T3IGV8F2SF0
Domain FQDN (Computer name if not domain joined): WIN-T3IGV8F2SF0
Computer FQDN: WIN-T3IGV8F2SF0
Computer os version: 6.3
Computer os build: 9600
WinRMS
NetBIOS computer name: WIN-T3IGV8F2SF0
NetBIOS domain name (Computer name if not domain joined): WIN-T3IGV8F2SF0
Domain FQDN (Computer name if not domain joined): WIN-T3IGV8F2SF0
Computer FQDN: WIN-T3IGV8F2SF0
Computer os version: 6.3
Computer os build: 9600
 ```
 
 How it works
 ===========
 The protocol order is SMB - RPC - WinRMs - WinRM.\
 The script checks for each target if it's up, and then tries to connect using each protocol specified.\
 For each protocol the script initiates an NTLM authentication and parses the NTLM Challenge sent by the target to retrieve the information.
 
 Notes
 ===========
 The script uses Impacket and requests for the networking functionality.\
 Examples from Impacket and pywinrm (not used in this project) were used to learn which functions to use, how they work and when to use them.
