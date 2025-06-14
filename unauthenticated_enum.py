# Imports
import ipaddress
import click
import os

from collectors.CollectorOutput import CollectorOutput
from collectors.RPCCollector import RPCCollector
from collectors.SMBCollector import SMBCollector
from collectors.WinRM.WinrmCollector import WinrmCollector
from collectors.WinRM.WinrmsCollector import WinrmsCollector

COLLECTORS = ["smb", "rpc", "winrm", "winrms", "all"]
@click.command()
@click.argument("ip", type=str)
@click.option(
    "--collector",
    type=click.Choice(COLLECTORS, case_sensitive=False),
    default="all",
    show_default=True,
    help=f"Which collector to use {COLLECTORS}",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Return results in JSON format"
)
def main(ip: str, collector: str, json_output: bool):
    """
    Enumerate hosts without authenticating.

    Accepts:
    - CIDR (e.g., 192.168.1.0/24)
    - Comma-separated list of IPs (e.g., 192.168.1.1,192.168.1.2)
    - File path with IPs (one per line)
    """
    targets = []

    # Detect and parse IP input
    try:
        if os.path.isfile(ip):
            with open(ip, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        targets.append(ipaddress.ip_address(line))
        elif "," in ip:
            for part in ip.split(","):
                targets.append(ipaddress.ip_address(part.strip()))
        else:
            network = ipaddress.IPv4Network(ip, strict=False)
            targets = list(network.hosts())
    except Exception as e:
        print("Input parsing error:", e)
        exit(1)
    targets = [str(target) for target in targets]
    all_results: list[CollectorOutput] = []

    if collector in ("smb", "all"):
        smb_results = SMBCollector(targets).run()
        all_results.extend(smb_results)

    if collector in ("rpc", "all"):
        rpc_results = RPCCollector(targets).run()
        all_results.extend(rpc_results)

    if collector in ("winrm", "all"):
        winrm_results = WinrmCollector(targets).run()
        all_results.extend(winrm_results)

    if collector in ("winrms", "all"):
        winrms_results = WinrmsCollector(targets).run()
        all_results.extend(winrms_results)

    if json_output:
        for result in all_results:
            print(result.model_dump_json())
    else:
        for result in all_results:
            result.pretty_log()

if __name__ == "__main__":
    main()
