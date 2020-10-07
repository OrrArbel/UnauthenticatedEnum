# Imports
from impacket import smb
from struct import pack, unpack
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5 import transport, epm, samr
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, MSRPCBindAck, DCERPCException
from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp
from impacket import ntlm
import requests
from base64 import b64decode
from impacket.smb import *
import socket
import argparse
import ipaddress
from os import system as runcommand

#Constants
SMB_PORT = 445
RPC_PORT = 135
WINRM_PORT = 5985
WINRMS_PORT = 5986
NDR64SYNTAX= ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')
OS_DICT = {10:{0:"Windows 10/Windows Server versions 1903/1909/2004"},6:{0:"Windows Vista/Windows Server 2008",1:"Windows 7/Windows Server 2008 R2",2:"Windows 8/Windows Server 2012",3:"Windows 8.1/Windows Server 2012 R2"},5:{0:"Windows 2000",2:"Windows Server 2003/R2 /Windows XP Professional x64 Edition",1:"Windows XP"}}

# Helper functions
def port_is_open(target,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((target,port))
        sock.close()
        return True
    except Exception as e:
        return False


def is_alive(target):
    # Check exit code of ping (0 = success, other = fail)
    return runcommand("ping -c 1 %s> /dev/null" % str(target)) == 0

def parse_ntlm_challenge(challenge,translateOS=False):
    '''
    Parses info from NTLM challenge.

    Parameters:
       challenge: NTLM challenge data.

    Returns:
        None (only print results)  
    '''

    # Convert the challenge data to a NTLMAuthChallegne object
    ntlmChallenge = ntlm.NTLMAuthChallenge(challenge)
    # Check if NTLM challenge includes any fields
    if ntlmChallenge['TargetInfoFields_len'] > 0:

        # Convert the fields to attribute/value pairs
        av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
        
        # NetBIOS Names
        if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
            try:
                server_name = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                print("NetBIOS name: %s" % server_name)
            except UnicodeDecodeError:
                # For some reason, we couldn't decode Unicode here.. silently discard the operation
                pass
        if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
            try:
                server_domain = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                print("NetBIOS domain name (Computer name if not domain joined): %s" % server_domain)
            except UnicodeDecodeError:
                # For some reason, we couldn't decode Unicode here.. silently discard the operation
                pass
            
        # DNS Names
        if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
            try:
                server_dns_domain_name = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode('utf-16le')
                print("Domain FQDN (Computer name if not domain joined): %s" % server_dns_domain_name)
            except UnicodeDecodeError:
                # For some reason, we couldn't decode Unicode here.. silently discard the operation
                pass

        if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
            try:
                server_dns_host_name = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode('utf-16le')
                print("Target FQDN: %s" % server_dns_host_name)
            except UnicodeDecodeError:
                # For some reason, we couldn't decode Unicode here.. silently discard the operation
                pass
            
        # OS version.
        if 'Version' in ntlmChallenge.fields:
            version = ntlmChallenge['Version']
            if len(version) >= 4:
                server_os_major, server_os_minor, server_os_build = unpack('<BBH',version[:4])
                print("Target OS version: %s.%s" % (server_os_major,server_os_minor))
                print("Target OS build: %s" % server_os_build)
                if translateOS:
                    print("OS name: %s" % OS_DICT[server_os_major][server_os_minor])


# Collector functions
def smb_collector(target):
    '''
    Enumerates information over SMB by initiating an NTLM authentication.

    Parameters:
       target: ip address of target.

    Returns:
        True if succeed, False if not.   
    '''
    # Check if SMB is open
    if not port_is_open(target,SMB_PORT):
        print("SMB is closed on %s" % target)
        return False

    # Create SMB object and craft packet to initiate NTLM authentication
    smb_obj = smb.SMB(target,target)
    packet = NewSMBPacket()
    sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
    sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
    sessionSetup['Data'] = SMBSessionSetupAndX_Extended_Data()
    sessionSetup['Parameters']['MaxBufferSize'] = 61440
    sessionSetup['Parameters']['MaxMpxCount'] = 2
    sessionSetup['Parameters']['VcNumber'] = 1
    sessionSetup['Parameters']['SessionKey'] = 0
    sessionSetup['Parameters']['Capabilities'] = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE | SMB.CAP_LARGE_READX | SMB.CAP_LARGE_WRITEX


    # NTLMSSP
    blob = SPNEGO_NegTokenInit()
    blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
    auth = ntlm.getNTLMSSPType1(smb_obj.get_client_name(),'',smb_obj._SignatureRequired, use_ntlmv2 = True)
    blob['MechToken'] = auth.getData()

    # Finish crafting packet
    sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
    sessionSetup['Data']['SecurityBlob'] = blob.getData()
    sessionSetup['Data']['NativeOS'] = 'Unix' # Generic irrelevant data
    sessionSetup['Data']['NativeLanMan'] = 'Samba' # Generic irrelevant data
    packet.addCommand(sessionSetup)

    # Send packet and get response
    smb_obj.sendSMB(packet)
    packet = smb_obj.recvSMB()

    # Extract the NTLM challenge
    sessionResponse = SMBCommand(packet['Data'][0])
    sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
    sessionData = SMBSessionSetupAndX_Extended_Response_Data(flags = packet['Flags2'])
    sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
    sessionData.fromString(sessionResponse['Data'])
    respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

    # Parse information from NTLM challenge
    parse_ntlm_challenge(respToken['ResponseToken'])
    print("OS name: %s" % sessionData['NativeOS'])

    # Check if computer is a server os workstation by it's OS name
    if sessionData['NativeOS'] and "server" in sessionData['NativeOS'].lower():
        print("Target is a server")
    else:
        print("Target is a workstation")
    return True


def winrms_collector(target):
    '''
    Enumerates information over WinRM by initiating an NTLM authentication.

    Parameters:
       target: ip address of target.

    Returns:
        True if succeed, False if not.   
    '''

    # Check if WinRM\S is open and assign url according to protocol selected
    if not port_is_open(target,WINRMS_PORT):
        print("WinRMS is closed on %s" % target)
        print("Tryig WinRM")
        if port_is_open(target,WINRM_PORT):
            print("Using WinRM")
            url = "http://%s:5985/wsman" % target
        else:
            print("WinRM is closed on %s" % target)
            return False
    else:
        url = "https://%s:5986/wsman" % target 
    
    # Initiate session by preparing a POST request to winrm's url on the target
    s = requests.Session()
    
    req = requests.Request('POST', url, data="")
    prepped = req.prepare()

    # Add NTLM Negotiate data to headers (empty authentication - no username and password). The data is encoded in Base64.
    prepped.headers['Authorization'] = "Negotiate TlRMTVNTUAABAAAAMZCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw=="

    # Send the request and get the response
    response = s.send(prepped,verify=False) #verify=False is for debugging with self-signed certificate

    # Extract the NTLM challenge by removing the "Negotiate" prefix and decoding from Base64
    challenge = b64decode(response.headers['WWW-Authenticate'].split('Negotiate ')[1])

    # Parse information from NTLM challenge
    parse_ntlm_challenge(challenge,translateOS=True)
    return True



def rpc_collector(target):
    '''
    Enumerates information over RPC by initiating an NTLM authentication, check processor architecture.
    Bind to Endpoint Mapper rpc interface which should always be available.

    Parameters:
       target: ip address of target.

    Returns:
        True if succeed, False if not.   
    '''

    # Check if RPC is open
    if not port_is_open(target,RPC_PORT):
        print("RPC is closed on %s" % target)
        return False
    
    # Construct rpc and dce structures
    stringBinding = r'ncacn_ip_tcp:%s[135]' % target
    rpctransport = transport.DCERPCTransportFactory(stringBinding)
    rpctransport.set_credentials('','')
    rpctransport.setRemoteHost(target)
    dce = rpctransport.get_dce_rpc()
    
    # Specify NTLM connection to retrieve relevant information
    dce.set_credentials('','')
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.connect()

    # Check if system architecture is x86 or x64 by trying to bind with x64 transfer syntax
    try:
        resp = dce.bind(epm.MSRPC_UUID_PORTMAP,transfer_syntax=NDR64SYNTAX)
        print("Target is x64")
    except DCERPCException as e:
        if str(e).find('syntaxes_not_supported') >= 0:
            resp = dce.bind(epm.MSRPC_UUID_PORTMAP)
            print("Target is x86")
        
    # Extract the NTLM challenge
    bindResp = MSRPCBindAck(resp.getData())

    # Parse information from NTLM challenge
    parse_ntlm_challenge(bindResp['auth_data'],translateOS=True)
    return True


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Enunmerate hosts without authenticating.')
    parser.add_argument('ip', type=str,help='Address or address range to scan, netmask required for address range (examples: single ip - 10.1.1.12 , class c semgment - 10.1.1.0/24)')
    args = parser.parse_args()
    
    # Try converting ip parameter to ipaddress
    try:
        targets = ipaddress.IPv4Network(args.ip)
    except Exception as e:
        print("IP address error: " + str(e))
        exit()
    
    # Enumerate targets
    for target in targets:
        if is_alive(str(target)):
            print(str(target) + " is up. Scanning...")
            print("\nSMB\n")
            smb_collector(str(target))
            print("\nRPC\n")
            result = rpc_collector(str(target))
            print("\nWinRM(S)\n")
            winrms_collector(str(target))
        else:
            print(str(target) + " is down.")



if __name__ == '__main__':
    main()
        
