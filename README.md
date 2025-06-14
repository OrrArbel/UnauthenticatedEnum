# UnauthenticatedEnum

A Python tool for unauthenticated NTLM enumeration of Windows hosts using multiple protocols. It
leverages [Impacket](https://github.com/fortra/impacket) to scan and extract host information without credentials. The
tool supports SMB, RPC, and WinRM protocols, parsing NTLM challenges to gather system details.

## Techniques Used

- **NTLM Challenge Parsing**: Extracts system and domain information from NTLM authentication challenges, using
  protocol-specific collectors.
- **RPC Binding for OS Architecture Detection**: Uses RPC binding to determine the remote host's operating system
  architechture (x64/x86) without authentication.

## Running the Tool

Clone the repository:

```sh
git clone https://github.com/OrrArbel/UnauthenticatedEnum.git
cd UnauthenticatedEnum
```

Install dependencies (uv required):

```sh
uv sync
```

Run the tool:

```sh
uv run unauthenticated_enum.py <target> [--collector <protocol>] [--json-output]
```

Examples:

```sh
uv run unauthenticated_enum.py 192.168.1.0/24
uv run unauthenticated_enum.py 192.168.1.1,192.168.1.2 --collector smb
uv run unauthenticated_enum.py targets.txt --json-output
```

- `<target>`: CIDR, comma-separated IPs, or a file with one IP per line.
- `--collector`: Choose from smb, rpc, winrm, winrms, or all (default: all).
- `--json-output`: Output results in JSON format.
