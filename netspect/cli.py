import typer
from typing_extensions import Annotated
from typing import List, Optional
import ipaddress

from netspect.core import discovery, dns_utils, interface_info
from netspect.utils.display import print_panel, console, print_error
from netspect import __version__ as app_version # We'll add __version__ later

# --- App Initialization ---
app = typer.Typer(
    name="NetSpect",
    help="🌐✨ A beautiful CLI for network analysis.",
    add_completion=False, # Disable shell completion for simplicity now
    no_args_is_help=True,
    rich_markup_mode="markdown"
)

# --- Helper Functions for CLI ---
def _parse_ports(port_str: Optional[str]) -> List[int]:
    """Parses a comma-separated string of ports/port ranges into a list of integers."""
    if not port_str: # Default ports
        return [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443]

    ports = set()
    parts = port_str.split(',')
    for part in parts:
        part = part.strip()
        if not part: continue
        if '-' in part:
            start, end = part.split('-', 1)
            try:
                start_port, end_port = int(start), int(end)
                if not (0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port):
                    raise ValueError("Port range invalid.")
                ports.update(range(start_port, end_port + 1))
            except ValueError:
                print_error(f"Invalid port range: {part}. Must be numbers between 1-65535.")
                raise typer.Exit(code=1)
        else:
            try:
                port_val = int(part)
                if not (0 < port_val <= 65535):
                    raise ValueError("Port number invalid.")
                ports.add(port_val)
            except ValueError:
                print_error(f"Invalid port number: {part}. Must be a number between 1-65535.")
                raise typer.Exit(code=1)
    if not ports:
        print_error("No valid ports specified.")
        raise typer.Exit(code=1)
    return sorted(list(ports))

def _validate_host(hostname_or_ip: str) -> str:
    """Validates if the input is a valid hostname or IP address."""
    try:
        # Check if it's a valid IP address
        ipaddress.ip_address(hostname_or_ip)
        return hostname_or_ip # It's a valid IP
    except ValueError:
        # Not an IP, check if it's a plausible hostname
        # Basic check: not empty, no leading/trailing dots, no spaces, etc.
        # A more robust check would involve regex for hostname characters.
        if not hostname_or_ip or hostname_or_ip.startswith('.') or hostname_or_ip.endswith('.') or ' ' in hostname_or_ip:
            print_error(f"Invalid hostname or IP address: '{hostname_or_ip}'")
            raise typer.BadParameter(f"'{hostname_or_ip}' is not a valid hostname or IP address.")
        return hostname_or_ip # Assume it's a hostname

# --- CLI Commands ---

@app.command(help="Ping a host to check reachability.")
def ping(
    target: Annotated[str, typer.Argument(help="The hostname or IP address to ping.", callback=_validate_host)],
    count: Annotated[int, typer.Option("-c", "--count", help="Number of ping packets to send.")] = 4,
    timeout: Annotated[int, typer.Option("-t", "--timeout", help="Timeout in seconds for each ping.")] = 2,
    verbose: Annotated[bool, typer.Option("-v", "--verbose", help="Enable verbose output from pythonping.")] = False,
):
    """Pings a host and displays results."""
    discovery.ping_host(target, count, timeout, verbose)

@app.command(help="Scan TCP ports on a target host.")
def scan(
    target: Annotated[str, typer.Argument(help="The hostname or IP address to scan.", callback=_validate_host)],
    ports_str: Annotated[Optional[str], typer.Option("-p", "--ports", help="Comma-separated ports/ranges (e.g., 80,443,1000-1024). Default: common ports.")] = None,
    timeout: Annotated[float, typer.Option("--timeout", help="Connection timeout in seconds for each port.")] = 0.5 # Shorter for faster scans
):
    """Scans TCP ports on a target host."""
    parsed_ports = _parse_ports(ports_str)
    discovery.scan_ports(target, parsed_ports, timeout)


@app.command(help="Perform DNS lookups for a hostname.")
def dns(
    hostname: Annotated[str, typer.Argument(help="The hostname to query.", callback=_validate_host)],
    types: Annotated[Optional[List[str]], typer.Option("-t", "--type", help=f"DNS record type(s) to query. Supported: {', '.join(dns_utils.SUPPORTED_RECORD_TYPES)}")] = None,
):
    """Performs DNS lookups for a hostname."""
    if not types:
        types = ["A", "AAAA", "MX"] # Default types
    
    # Validate types
    valid_types = [t.upper() for t in types if t.upper() in dns_utils.SUPPORTED_RECORD_TYPES]
    invalid_types = [t for t in types if t.upper() not in dns_utils.SUPPORTED_RECORD_TYPES]
    if invalid_types:
        print_error(f"Unsupported DNS record type(s): {', '.join(invalid_types)}. Supported are: {', '.join(dns_utils.SUPPORTED_RECORD_TYPES)}")
        if not valid_types:
            raise typer.Exit(code=1)
        console.print(f"[yellow]Ignoring invalid types and proceeding with: {', '.join(valid_types)}[/yellow]")

    if not valid_types: # If default was overridden with only invalid types
        print_error(f"No valid DNS record types specified. Supported are: {', '.join(dns_utils.SUPPORTED_RECORD_TYPES)}")
        raise typer.Exit(code=1)

    # Get CNAME first if A or AAAA is requested, to show the resolution path
    if any(t in valid_types for t in ["A", "AAAA"]):
        cname = dns_utils.get_canonical_name(hostname)
        if cname and cname.lower() != hostname.lower():
            console.print(f"[dim]{hostname} is an alias for [bold cyan]{cname}[/bold cyan][/dim]")
            # Optionally, you could change the 'hostname' for subsequent lookups to the cname
            # hostname = cname # If you want all lookups to be against the canonical name

    dns_utils.resolve_hostname(hostname, valid_types)


@app.command(name="iface", help="Show local network interface information.")
def show_interfaces():
    """Shows local network interface information."""
    interface_info.get_interface_details()

def version_callback(value: bool):
    if value:
        console.print(f"NetSpect Version: [bold cyan]{app_version}[/bold cyan]")
        raise typer.Exit()

@app.callback()
def main_callback(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool],
        typer.Option("--version", callback=version_callback, is_eager=True, help="Show application version and exit."),
    ] = None,
):
    """
    NetSpect: Your friendly neighborhood network tool.
    Use --help for command specific options.
    """
    if ctx.invoked_subcommand is None and not version : # Print banner if no command is given (and not --version)
        print_panel(
            "[bold bright_magenta]NetSpect[/] - [cyan]Network Analysis Tool[/]\n"
            "Type `[bright_yellow]netspect --help[/]` for available commands.",
            title="Welcome!",
            style="bold green"
        )

# This is to allow running with `python -m netspect.cli`
if __name__ == "__main__":
    app()
