import dns.resolver
import socket
from typing import List, Dict, Union

from netspect.utils.display import print_info, print_error, console, display_table

SUPPORTED_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "SRV"]

def resolve_hostname(hostname: str, record_types: List[str] = ["A", "AAAA"]) -> Dict[str, List[str]]:
    """
    Resolves a hostname to IP addresses for specified record types.
    """
    results: Dict[str, List[str]] = {rtype: [] for rtype in record_types}
    print_info(f"Performing DNS lookup for {hostname}, types: {', '.join(record_types)}...")

    resolver = dns.resolver.Resolver()
    # Optionally configure resolver (e.g., resolver.nameservers = ['8.8.8.8'])

    for r_type in record_types:
        if r_type.upper() not in SUPPORTED_RECORD_TYPES:
            print_error(f"Unsupported record type: {r_type}. Skipping.")
            continue
        try:
            answers = resolver.resolve(hostname, r_type.upper())
            for rdata in answers:
                if r_type.upper() == "MX":
                    results[r_type].append(f"Preference: {rdata.preference}, Exchange: {rdata.exchange.to_text(omit_final_dot=True)}")
                elif r_type.upper() == "SOA":
                    results[r_type].append(
                        f"MNAME: {rdata.mname.to_text(omit_final_dot=True)}, "
                        f"RNAME: {rdata.rname.to_text(omit_final_dot=True)}, "
                        f"Serial: {rdata.serial}"
                    )
                elif r_type.upper() == "TXT":
                    # TXT records can be multiple strings, join them
                    results[r_type].append(" ".join(txt_string.decode('utf-8') for txt_string in rdata.strings))
                elif r_type.upper() == "SRV":
                    results[r_type].append(
                        f"Priority: {rdata.priority}, Weight: {rdata.weight}, "
                        f"Port: {rdata.port}, Target: {rdata.target.to_text(omit_final_dot=True)}"
                    )
                else: # A, AAAA, CNAME, NS
                    results[r_type].append(rdata.to_text(omit_final_dot=True))
        except dns.resolver.NXDOMAIN:
            print_error(f"Hostname {hostname} not found (NXDOMAIN) for type {r_type}.")
            results[r_type].append("NXDOMAIN")
        except dns.resolver.NoAnswer:
            print_warning(f"No {r_type} records found for {hostname}.")
            results[r_type].append("No Answer")
        except dns.exception.Timeout:
            print_error(f"DNS query timed out for {hostname}, type {r_type}.")
            results[r_type].append("Timeout")
        except Exception as e:
            print_error(f"Error resolving {hostname} for type {r_type}: {e}")
            results[r_type].append(f"Error: {e}")
    
    # Display results
    table_data = []
    for r_type, r_values in results.items():
        if r_values:
            for val in r_values:
                table_data.append({"Record Type": r_type.upper(), "Value": val})
        else: # Should not happen if initialized properly, but as a fallback
             table_data.append({"Record Type": r_type.upper(), "Value": "No data"})


    if table_data:
        display_table(table_data, title=f"DNS Records for {hostname}")
    else:
        print_warning(f"No DNS information retrieved for {hostname}.")

    return results

def get_canonical_name(hostname: str) -> Union[str, None]:
    """Gets the canonical name (CNAME) if one exists."""
    try:
        # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        # The first item is the canonical hostname
        cname, _, _ = socket.gethostbyname_ex(hostname)
        if cname != hostname: # Only return if it's different (i.e., a CNAME was followed)
            return cname
    except socket.gaierror:
        pass # Host not found or other error, will be handled by main resolve function
    except Exception:
        pass
    return None
