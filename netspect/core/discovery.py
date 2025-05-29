import socket
from typing import List, Tuple, Optional
from pythonping import ping as execute_ping
from pythonping.executor import SuccessOn # Import for type hinting if needed
from rich.live import Live
from rich.text import Text

from netspect.utils.display import get_progress_bar, print_success, print_error, print_info, console

def ping_host(target: str, count: int = 4, timeout: int = 2, verbose: bool = False) -> bool:
    """
    Pings a host and displays results.
    Returns True if any pings were successful, False otherwise.
    """
    print_info(f"Pinging {target} with {count} packets, timeout {timeout}s...")
    all_successful = True
    total_rtt = 0
    successful_pings = 0
    min_rtt = float('inf')
    max_rtt = 0.0

    try:
        # pythonping.ping returns a ResponseList object
        response_list = execute_ping(target, count=count, timeout=timeout, verbose=verbose)

        for response in response_list: # Iterate through individual Response objects
            if response.success:
                rtt_ms = response.time_elapsed_ms
                total_rtt += rtt_ms
                successful_pings += 1
                min_rtt = min(min_rtt, rtt_ms)
                max_rtt = max(max_rtt, rtt_ms)
                console.print(f"Reply from {response.message.split()[2][:-1]}: bytes={response.message.split()[3]} time={rtt_ms:.2f}ms TTL={response.message.split()[4].split('=')[1]}")
            else:
                console.print(f"[red]Request timed out or host unreachable: {response.error_message}[/red]")
                all_successful = False
        
        if successful_pings > 0:
            avg_rtt = total_rtt / successful_pings
            print_success(f"\nPing statistics for {target}:")
            console.print(f"  Packets: Sent = {count}, Received = {successful_pings}, Lost = {count - successful_pings} ({(count - successful_pings) / count * 100:.1f}% loss)")
            console.print(f"Approximate round trip times in milli-seconds:")
            console.print(f"  Minimum = {min_rtt:.2f}ms, Maximum = {max_rtt:.2f}ms, Average = {avg_rtt:.2f}ms")
            return True
        else:
            print_error(f"\nNo successful pings to {target}.")
            return False

    except Exception as e:
        print_error(f"Error pinging {target}: {e}")
        return False


def scan_ports(target: str, ports: List[int], timeout: float = 1.0) -> List[Tuple[int, str]]:
    """
    Scans a list of TCP ports on a target host.
    Returns a list of tuples (port, status), where status is 'open' or 'closed'.
    """
    open_ports: List[Tuple[int, str]] = []
    closed_ports_count = 0 # For summary, not individual listing

    try:
        target_ip = socket.gethostbyname(target)
        print_info(f"Scanning {target} ({target_ip}) for {len(ports)} port(s)...")
    except socket.gaierror:
        print_error(f"Cannot resolve hostname: {target}. Please check the name or use an IP address.")
        return []
    except Exception as e:
        print_error(f"An unexpected error occurred resolving hostname: {e}")
        return []


    progress = get_progress_bar()
    with Live(progress, refresh_per_second=10, console=console) as live:
        task = progress.add_task(f"[cyan]Scanning ports on {target}", total=len(ports))

        for port in ports:
            progress.update(task, advance=1, description=f"[cyan]Scanning port {port} on {target}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service_name = "unknown"
                try:
                    service_name = socket.getservbyport(port, "tcp")
                except OSError: # Port not in services list
                    pass
                except Exception: # Other potential errors
                    pass
                open_ports.append((port, "open", service_name))
            else:
                closed_ports_count += 1
            sock.close()
        progress.update(task, description=f"[green]Scan complete for {target}!", completed=len(ports))


    if open_ports:
        print_success(f"\nOpen ports on {target} ({target_ip}):")
        for port, status, service in open_ports:
            console.print(f"  [bold green]Port {port:<5}[/bold green] ({service}) is {status}")
    else:
        print_warning(f"\nNo open ports found on {target} ({target_ip}) in the scanned range.")
    
    print_info(f"Summary: {len(open_ports)} open, {closed_ports_count} closed/filtered.")
    return [(p, s) for p, s, _ in open_ports] # Return only port and status for simplicity
