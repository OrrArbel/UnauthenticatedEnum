import socket
from struct import unpack

from impacket import ntlm

from collectors.CollectorOutput import CollectorOutput, OSInfo
from utils.constants import OS_DICT
import logging

logger = logging.getLogger(__name__)


def is_port_open(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((target, port))
        sock.close()
        return True
    except Exception as e:
        logger.warning(f"Port {port} on {target} is not open: {e}")
        return False


def parse_ntlm_challenge(challenge: str | bytes, translate_os=False):
    """
    Parses info from NTLM challenge.

    Parameters:
       translate_os: Print OS name in friendly format
       challenge: NTLM challenge data.

    Returns:
        CollectorOutput instance with parsed results
    """
    # Convert the challenge data to a NTLMAuthChallenge object
    ntlm_challenge = ntlm.NTLMAuthChallenge(challenge)

    server_name = None
    server_domain = None
    server_dns_domain_name = None
    server_dns_host_name = None
    os_name = None
    os_version = None
    os_build = None

    # Check if NTLM challenge includes any fields
    if ntlm_challenge["TargetInfoFields_len"] > 0:
        # Convert the fields to attribute/value pairs
        av_pairs = ntlm.AV_PAIRS(
            ntlm_challenge["TargetInfoFields"][: ntlm_challenge["TargetInfoFields_len"]]
        )

        # NetBIOS Names
        if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
            try:
                server_name = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode("utf-16le")
            except UnicodeDecodeError:
                # For some reason, we couldn't decode Unicode here.. silently discard the operation
                pass
        if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
            try:
                server_domain = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode(
                    "utf-16le"
                )
            except UnicodeDecodeError:
                # For some reason, we couldn't decode Unicode here.. silently discard the operation
                pass

        # DNS Names
        if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
            try:
                server_dns_domain_name = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][
                    1
                ].decode("utf-16le")
            except UnicodeDecodeError:
                # For some reason, we couldn't decode Unicode here.. silently discard the operation
                pass

        if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
            try:
                server_dns_host_name = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode(
                    "utf-16le"
                )
            except UnicodeDecodeError:
                # For some reason, we couldn't decode Unicode here.. silently discard the operation
                pass

    # OS version.
    if "Version" in ntlm_challenge.fields:
        version = ntlm_challenge["Version"]
        if len(version) >= 4:
            server_os_major, server_os_minor, server_os_build = unpack(
                "<BBH", version[:4]
            )
            os_version = f"{server_os_major}.{server_os_minor}"
            os_build = str(server_os_build)
            if translate_os:
                try:
                    os_name = OS_DICT[server_os_major][server_os_minor]
                except Exception:
                    os_name = None

    # Compose CollectorOutput
    os_info = OSInfo(name=os_name or "", version=os_version or "", build=os_build or "")
    result = CollectorOutput(
        collector="NTLM",
        target="",  # Not available from challenge
        domain_fqdn=server_dns_domain_name or "",
        domain_netbios=server_domain or "",
        hostname_fqdn=server_dns_host_name or "",
        hostname_netbios=server_name or "",
        os=os_info,
    )

    return result
