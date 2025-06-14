from collectors.BaseNTLMCollector import BaseNTLMCollector
from impacket.dcerpc.v5 import epm, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, DCERPCException, MSRPCBindAck

from collectors.CollectorOutput import CollectorOutput
from utils.constants import NDR64Syntax
from utils.utils import parse_ntlm_challenge


class RPCCollector(BaseNTLMCollector):
    def __init__(self, targets: list[str]):
        super().__init__(targets)

    @property
    def name(self) -> str:
        return "RPC"

    @property
    def port(self) -> int:
        return 135

    def collect_data(self, target: str) -> CollectorOutput | None:
        # Construct rpc and dce structures
        string_binding = rf"ncacn_ip_tcp:{target}[{self.port}]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_credentials("", "")
        rpc_transport.setRemoteHost(target)
        dce = rpc_transport.get_dce_rpc()

        # Specify NTLM connection to retrieve relevant information
        dce.set_credentials("", "")
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        try:
            dce.connect()
        except Exception as e:
            print(f"RPC Error, probably rejected - {e}")
        # Check if system architecture is x86 or x64 by trying to bind with x64 transfer syntax
        try:
            resp = dce.bind(epm.MSRPC_UUID_PORTMAP, transfer_syntax=NDR64Syntax)
            is_x64 = True
        except DCERPCException as e:
            if str(e).find("syntaxes_not_supported") >= 0:
                try:
                    resp = dce.bind(epm.MSRPC_UUID_PORTMAP)
                except Exception as e:
                    print(f"Unexpected error - {e}")
                    return None
                else:
                    is_x64 = False
            else:
                print(f"Unexpected error - {e}")
                return None
        except Exception as e:
            print(f"Unexpected error - {e}")
            return None

        # Extract the NTLM challenge
        bind_resp = MSRPCBindAck(resp.getData())

        # Parse information from NTLM challenge
        collector_output: CollectorOutput = parse_ntlm_challenge(
            bind_resp["auth_data"], translate_os=True
        )
        collector_output.bitness = "x64" if is_x64 else "x86"
        return collector_output