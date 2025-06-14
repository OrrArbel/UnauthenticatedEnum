import logging

from impacket import ntlm
from impacket.smb import (
    SMB,
    NewSMBPacket,
    SMBCommand,
    SMBSessionSetupAndX_Extended_Data,
    SMBSessionSetupAndX_Extended_Parameters,
    SMBSessionSetupAndX_Extended_Response_Data,
    SMBSessionSetupAndX_Extended_Response_Parameters,
)
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

from collectors.BaseNTLMCollector import BaseNTLMCollector
from collectors.CollectorOutput import CollectorOutput
from utils.utils import parse_ntlm_challenge

logger = logging.getLogger(__name__)


class SMBCollector(BaseNTLMCollector):
    def __init__(self, targets: list[str]):
        super().__init__(targets)

    @property
    def name(self) -> str:
        return "SMB"

    @property
    def port(self) -> int:
        return 445

    def collect_data(self, target: str) -> CollectorOutput | None:
        # Create SMB connection and craft packet to initiate NTLM authentication
        try:
            smb_obj = SMB(target, target)
        except Exception as e:
            logger.error(f"SMB Error probably rejected - {e}")
            return None
        packet = self.get_smb_negotiate_packet(smb_obj)

        # Send packet and get response
        smb_obj.sendSMB(packet)
        packet = smb_obj.recvSMB()

        # Extract the NTLM challenge
        session_response = SMBCommand(packet["Data"][0])
        session_parameters = SMBSessionSetupAndX_Extended_Response_Parameters(
            session_response["Parameters"]
        )
        session_data = SMBSessionSetupAndX_Extended_Response_Data(
            flags=packet["Flags2"]
        )
        session_data["SecurityBlobLength"] = session_parameters["SecurityBlobLength"]
        session_data.fromString(session_response["Data"])
        resp_token = SPNEGO_NegTokenResp(session_data["SecurityBlob"])

        # Parse information from NTLM challenge
        collector_output: CollectorOutput = parse_ntlm_challenge(
            resp_token["ResponseToken"]
        )
        collector_output.os.name = session_data["NativeOS"]

        # Check if computer is a server os workstation by its OS name
        if session_data["NativeOS"] and "server" in session_data["NativeOS"].lower():
            collector_output.host_type = "Server"
        else:
            collector_output.host_type = "Workstation"

        return collector_output

    def get_smb_negotiate_packet(self, smb_obj):
        packet = NewSMBPacket()
        session_setup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        session_setup["Parameters"] = SMBSessionSetupAndX_Extended_Parameters()
        session_setup["Data"] = SMBSessionSetupAndX_Extended_Data()
        session_setup["Parameters"]["MaxBufferSize"] = 61440
        session_setup["Parameters"]["MaxMpxCount"] = 2
        session_setup["Parameters"]["VcNumber"] = 1
        session_setup["Parameters"]["SessionKey"] = 0
        session_setup["Parameters"]["Capabilities"] = (
            SMB.CAP_EXTENDED_SECURITY
            | SMB.CAP_USE_NT_ERRORS
            | SMB.CAP_UNICODE
            | SMB.CAP_LARGE_READX
            | SMB.CAP_LARGE_WRITEX
        )
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [
            TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
        ]
        auth = ntlm.getNTLMSSPType1(
            smb_obj.get_client_name(), "", smb_obj._SignatureRequired, use_ntlmv2=True
        )
        blob["MechToken"] = auth.getData()
        session_setup["Parameters"]["SecurityBlobLength"] = len(blob)
        session_setup["Data"]["SecurityBlob"] = blob.getData()
        session_setup["Data"]["NativeOS"] = "Unix"  # Generic irrelevant data
        session_setup["Data"]["NativeLanMan"] = "Samba"  # Generic irrelevant data
        packet.addCommand(session_setup)
        return packet
