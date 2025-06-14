from typing import Literal, Optional
from rich.console import Console
from rich.table import Table
import pydantic


class OSInfo(pydantic.BaseModel):
    name: str
    version: str
    build: str


class CollectorOutput(pydantic.BaseModel):
    collector: str
    target: str
    bitness: Optional[Literal["x86", "x64"]] = None
    host_type: Optional[Literal["Workstation", "Server"]] = None
    domain_fqdn: str
    domain_netbios: str
    hostname_fqdn: str
    hostname_netbios: str
    os: OSInfo

    def pretty_log(self) -> None:
        console = Console()
        table = Table(title=f"Scan Result for {self.target} ({self.collector.upper()})")

        table.add_column("Field", style="bold green")
        table.add_column("Value", style="white")

        table.add_row("Bitness", self.bitness)
        table.add_row("Host Type", self.host_type)
        table.add_row("Domain (FQDN)", self.domain_fqdn)
        table.add_row("Domain (NetBIOS)", self.domain_netbios)
        table.add_row("Hostname (FQDN)", self.hostname_fqdn)
        table.add_row("Hostname (NetBIOS)", self.hostname_netbios)
        table.add_row("OS Name", self.os.name)
        table.add_row("OS Version", self.os.version)
        table.add_row("OS Build", self.os.build)

        console.print(table)

    def json_log(self) -> None:
         print(self.model_dump_json())
