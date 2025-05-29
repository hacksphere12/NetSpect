import psutil
from typing import List, Dict, Any

from netspect.utils.display import display_table, print_info, print_error

def get_interface_details() -> List[Dict[str, Any]]:
    """
    Retrieves and displays details for all network interfaces.
    """
    print_info("Fetching local network interface information...")
    ifaces_data = []
    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, snic_list in addresses.items():
            iface_info = {"Interface": name, "MAC Address": "", "IP Address (IPv4)": "", "Netmask (IPv4)": "", "IP Address (IPv6)": "", "Status": "N/A"}
            
            if name in stats:
                iface_info["Status"] = "Up" if stats[name].isup else "Down"
                # Add more stats if desired:
                # iface_info["Speed (Mbps)"] = stats[name].speed
                # iface_info["MTU"] = stats[name].mtu
            
            for snic in snic_list:
                if snic.family == psutil.AF_LINK: # MAC Address
                    iface_info["MAC Address"] = snic.address
                elif snic.family == socket.AF_INET: # IPv4
                    iface_info["IP Address (IPv4)"] = snic.address
                    iface_info["Netmask (IPv4)"] = snic.netmask
                elif snic.family == socket.AF_INET6: # IPv6
                    # Prefer non-link-local IPv6 if multiple exist
                    if not iface_info["IP Address (IPv6)"] or not iface_info["IP Address (IPv6)"].startswith("fe80"):
                        iface_info["IP Address (IPv6)"] = snic.address.split('%')[0] # Remove scope ID if present

            ifaces_data.append(iface_info)
        
        if ifaces_data:
            # Define explicit column order for better presentation
            columns = ["Interface", "Status", "IP Address (IPv4)", "Netmask (IPv4)", "IP Address (IPv6)", "MAC Address"]
            display_table(ifaces_data, title="Network Interfaces", columns=columns)
        else:
            print_error("No network interfaces found or psutil could not retrieve them.")

    except Exception as e:
        print_error(f"Could not retrieve interface information: {e}")
    
    return ifaces_data
