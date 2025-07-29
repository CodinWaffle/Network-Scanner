import scapy.all as scapy
import time
from utils import get_ip_range, auto_detect_monitor_interface, get_interface_info
from wifi_scanner import WiFiScanner
from animation import clear_screen, print_with_effect, start_spinner, stop_spinner
from deauth import DeauthAttack
from device_identifier import DeviceIdentifier
from typing import List, Dict, Optional

# Global variables for device storage and identification
scanned_devices = []  # Store scan results between menu operations
device_identifier = DeviceIdentifier()  # Initialize device identifier

def print_banner():
    banner = '''
    █▄░█ █▀▀ ▀█▀ █░█░█ █▀█ █▀█ █▄▀   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
    █░▀█ ██▄ ░█░ ▀▄▀▄▀ █▄█ █▀▄ █░█   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
    '''
    print_with_effect(banner)

def clean_mac_address(mac_address: str) -> str:
    """
    Clean and normalize MAC address format.
    
    Args:
        mac_address: Raw MAC address string
        
    Returns:
        Cleaned MAC address in XX:XX:XX:XX:XX:XX format
    """
    if not mac_address:
        return mac_address
    
    # Remove trailing colons and whitespace
    cleaned = mac_address.strip().rstrip(':')
    
    # Ensure proper MAC format (XX:XX:XX:XX:XX:XX)
    if len(cleaned.replace(':', '')) == 12:
        return cleaned
    
    return mac_address  # Return original if cleaning fails

def scan_network():
    global scanned_devices
    devices = []
    ip_range = get_ip_range()
    
    # Initialize WiFi scanner
    try:
        wifi_scanner = WiFiScanner()
        spinner_event, spinner_thread = start_spinner("Scanning for WiFi networks")
        wifi_networks = wifi_scanner.scan_networks()
        stop_spinner(spinner_event, spinner_thread)
        
        for network in wifi_networks:
            devices.append({
                'ssid': network['ssid'],
                'mac_address': clean_mac_address(network['bssid']),
                'signal_strength': network['signal'],
                'security': network['security'],
                'vulnerability_status': network['vulnerability_status'],
                'type': 'wifi'
            })
    except Exception as e:
        if 'spinner' in locals():
            stop_spinner(spinner_event, spinner_thread)
        print(f"\nWiFi scanning error: {str(e)}")

    # Regular network scan
    spinner_event, spinner_thread = start_spinner("Scanning local network devices")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    stop_spinner(spinner_event, spinner_thread)

    # Process devices found through ARP
    for element in answered_list:
        device_info = {
            'ip_address': element[1].psrc,
            'mac_address': clean_mac_address(element[1].hwsrc),
            'ssid': 'Local Network',
            'type': 'device'
        }
        devices.append(device_info)

    # Enhance devices with identification information
    spinner_event, spinner_thread = start_spinner("Identifying device types")
    enhanced_devices = identify_and_categorize_devices(devices)
    stop_spinner(spinner_event, spinner_thread)
    
    # Store in global variable for device selection
    scanned_devices = enhanced_devices
    
    return enhanced_devices

def print_menu():
    menu = (
        "\n    Choose an option:\n"
        "    1. Scan for WiFi Networks\n"
        "    2. Scan Local Network Devices\n"
        "    3. Full Network Scan (WiFi + Devices)\n"
        "    4. Scan for Available Wi-Fi SSIDs (Select & Auto-Interface)\n"
        "    5. Scan and Kick Device (Smart Selection)\n"
        "    6. Exit\n"
        "\n"
        "    Enter your choice (1-6): "
    )
    return input(menu)

def display_wifi_networks(networks):
    if not networks:
        print("No WiFi networks found.")
        return
    
    print("\n══════════════════════════════════════════════════════════════════════")
    print("Found WiFi Networks:")
    print("══════════════════════════════════════════════════════════════════════")
    
    for network in networks:
        details = [
            f"+- SSID: {network['ssid']}",
            f"|- BSSID: {network['mac_address']}",
            f"|- Signal Strength: {network['signal_strength']}dBm",
            f"|- Security: {network['security']}",
            f"\\- Vulnerabilities: {network['vulnerability_status']}"
        ]
        print("\n".join(details))

def display_local_devices(devices):
    if not devices:
        print("No devices found on the network.")
        return
    
    print("\n══════════════════════════════════════════════════════════════════════")
    print(f"Found Devices: {len(devices)} devices connected")
    print("══════════════════════════════════════════════════════════════════════")
    
    for device in devices:
        details = [
            f"+- MAC Address: {device['mac_address']}",
            f"|- IP Address: {device.get('ip_address', 'Unknown')}",
            f"|- Network: {device.get('ssid', 'Local Network')}",
            f"\\- Status: Connected"
        ]
        print("\n".join(details))

def deduplicate_devices(devices: List[Dict]) -> List[Dict]:
    """
    Remove duplicate devices based on MAC address, keeping the one with most information.
    
    Args:
        devices: List of device information
        
    Returns:
        List of deduplicated devices
    """
    seen_macs = {}
    deduplicated = []
    
    for device in devices:
        mac_address = clean_mac_address(device.get('mac_address', ''))
        if not mac_address:
            continue
            
        # If we haven't seen this MAC before, add it
        if mac_address not in seen_macs:
            seen_macs[mac_address] = device
        else:
            # If we have seen it, keep the one with more information
            existing = seen_macs[mac_address]
            
            # Prefer device with IP address
            if device.get('ip_address') and not existing.get('ip_address'):
                seen_macs[mac_address] = device
            # Prefer device with signal strength (WiFi info)
            elif device.get('signal_strength') and not existing.get('signal_strength'):
                # Merge the information
                merged = existing.copy()
                merged.update({k: v for k, v in device.items() if v and not merged.get(k)})
                seen_macs[mac_address] = merged
    
    return list(seen_macs.values())

def identify_and_categorize_devices(devices: List[Dict]) -> List[Dict]:
    """
    Enhance devices with identification information and assign sequential IDs.
    
    Args:
        devices: List of basic device information
        
    Returns:
        List of enhanced devices with identification data
    """
    # First deduplicate devices
    deduplicated_devices = deduplicate_devices(devices)
    
    enhanced_devices = []
    device_id = 1
    
    for device in deduplicated_devices:
        mac_address = clean_mac_address(device.get('mac_address', ''))
        ip_address = device.get('ip_address', '')
        
        # Get device identification
        identification = device_identifier.identify_device_type(
            mac_address=mac_address,
            ip_address=ip_address
        )
        
        # Create enhanced device info
        enhanced_device = {
            'id': device_id,
            'ip_address': ip_address,
            'mac_address': mac_address,
            'ssid': device.get('ssid', 'Local Network'),
            'signal_strength': device.get('signal_strength'),
            'security': device.get('security'),
            'vulnerability_status': device.get('vulnerability_status'),
            'type': device.get('type', 'device'),
            'device_type': identification['device_type'],
            'vendor': identification['vendor'],
            'device_name': identification['device_name'],
            'confidence': identification['confidence'],
            'type_icon': identification['type_icon']
        }
        
        enhanced_devices.append(enhanced_device)
        device_id += 1
    
    return enhanced_devices

def display_categorized_device_menu(devices: List[Dict], current_filter: str = "all") -> None:
    """
    Display devices organized by category with selection numbers.
    
    Args:
        devices: List of enhanced device information
        current_filter: Current filter applied ("all" or device type)
    """
    if not devices:
        print("\n══════════════════════════════════════════════════════════════════════")
        print("No devices found for deauthentication.")
        print("══════════════════════════════════════════════════════════════════════")
        return
    
    # Filter devices if needed
    if current_filter != "all":
        devices = device_identifier.filter_devices_by_type(devices, current_filter)
        if not devices:
            print(f"\n══════════════════════════════════════════════════════════════════════")
            print(f"No {current_filter} devices found.")
            print("══════════════════════════════════════════════════════════════════════")
            return
    
    # Group devices by type
    device_groups = {}
    for device in devices:
        device_type = device['device_type']
        if device_type not in device_groups:
            device_groups[device_type] = []
        device_groups[device_type].append(device)
    
    # Display header
    total_devices = len(devices)
    filter_text = f" (filtered: {current_filter})" if current_filter != "all" else ""
    print(f"\n══════════════════════════════════════════════════════════════════════")
    print(f"Available Devices for Deauthentication ({total_devices} devices found){filter_text}:")
    print("══════════════════════════════════════════════════════════════════════")
    
    # Display devices by category
    for device_type in sorted(device_groups.keys()):
        devices_in_group = device_groups[device_type]
        category_name = device_identifier.get_device_category_display_name(device_type)
        icon = devices_in_group[0]['type_icon']
        
        print(f"\n{icon} {category_name} ({len(devices_in_group)} devices):")
        
        for device in devices_in_group:
            # Format device display line
            device_line = f"[{device['id']}] {device['device_name']}"
            
            if device['vendor'] != "Unknown":
                device_line += f" | {device['vendor']}"
            
            device_line += f" | MAC: {device['mac_address']}"
            
            if device.get('ip_address'):
                device_line += f" | IP: {device['ip_address']}"
            
            if device.get('signal_strength'):
                device_line += f" | Signal: {device['signal_strength']}dBm"
            
            # Add confidence indicator for identification
            confidence = device.get('confidence', 0)
            if confidence < 0.7:
                device_line += " | (?)"  # Low confidence indicator
            
            print(device_line)
    
    print(f"\n══════════════════════════════════════════════════════════════════════")

def get_device_selection_with_filters(devices: List[Dict]) -> Optional[Dict]:
    """
    Handle device selection with filtering options.
    
    Args:
        devices: List of enhanced device information
        
    Returns:
        Selected device dictionary or None if cancelled
    """
    current_filter = "all"
    
    while True:
        # Display current devices
        display_categorized_device_menu(devices, current_filter)
        
        if not devices or (current_filter != "all" and not device_identifier.filter_devices_by_type(devices, current_filter)):
            print("\nNo devices available for selection.")
            return None
        
        # Get filtered devices for selection
        filtered_devices = device_identifier.filter_devices_by_type(devices, current_filter) if current_filter != "all" else devices
        
        # Show options
        print("\nOptions:")
        print("• Enter device number to kick (e.g., 1, 2, 3...)")
        print("• Enter 'f <type>' to filter by device type:")
        print("  - f mobile    (phones, tablets)")
        print("  - f computer  (laptops, desktops)")
        print("  - f iot       (smart home devices)")
        print("  - f gaming    (consoles)")
        print("  - f network   (routers, access points)")
        print("  - f all       (show all devices)")
        print("• Enter 'q' to quit")
        
        user_input = input("\nYour choice: ").strip().lower()
        
        # Handle quit
        if user_input == 'q':
            return None
        
        # Handle filter commands
        if user_input.startswith('f '):
            filter_type = user_input[2:].strip()
            valid_filters = ['all', 'mobile', 'computer', 'iot', 'gaming', 'network', 'media']
            
            if filter_type in valid_filters:
                current_filter = filter_type
                clear_screen()
                print_banner()
                continue
            else:
                print(f"\nInvalid filter type: {filter_type}")
                print("Valid filters: all, mobile, computer, iot, gaming, network, media")
                input("Press Enter to continue...")
                clear_screen()
                print_banner()
                continue
        
        # Handle device selection
        try:
            device_id = int(user_input)
            
            # Find device with matching ID in filtered list
            selected_device = None
            for device in filtered_devices:
                if device['id'] == device_id:
                    selected_device = device
                    break
            
            if selected_device:
                # Show confirmation
                if confirm_device_selection(selected_device):
                    return selected_device
                else:
                    clear_screen()
                    print_banner()
                    continue
            else:
                print(f"\nInvalid device number: {device_id}")
                print(f"Please enter a number between 1 and {len(filtered_devices)}")
                input("Press Enter to continue...")
                clear_screen()
                print_banner()
                continue
                
        except ValueError:
            print(f"\nInvalid input: {user_input}")
            print("Please enter a device number, filter command (f <type>), or 'q' to quit.")
            input("Press Enter to continue...")
            clear_screen()
            print_banner()
            continue

def get_device_selection_with_instant_kick(devices: List[Dict], gateway_mac: str = None) -> Optional[Dict]:
    """
    Handle device selection with instant kick functionality.
    
    Args:
        devices: List of enhanced device information
        gateway_mac: Auto-detected gateway MAC address
        
    Returns:
        Selected device dictionary or None if cancelled
    """
    current_filter = "all"
    
    while True:
        # Display current devices
        display_categorized_device_menu(devices, current_filter)
        
        if not devices or (current_filter != "all" and not device_identifier.filter_devices_by_type(devices, current_filter)):
            print("\nNo devices available for selection.")
            return None
        
        # Get filtered devices for selection
        filtered_devices = device_identifier.filter_devices_by_type(devices, current_filter) if current_filter != "all" else devices
        
        # Show gateway status
        gateway_status = f"✅ Auto-detected: {gateway_mac}" if gateway_mac else "❌ Not detected"
        print(f"\nGateway MAC: {gateway_status}")
        
        # Show options
        print("\nOptions:")
        print("• Enter device number to kick (e.g., 1, 2, 3...)")
        if gateway_mac:
            print("• Enter 'i <number>' for INSTANT KICK (e.g., i 1, i 2...)")
        print("• Enter 'f <type>' to filter by device type:")
        print("  - f mobile    (phones, tablets)")
        print("  - f computer  (laptops, desktops)")
        print("  - f iot       (smart home devices)")
        print("  - f gaming    (consoles)")
        print("  - f network   (routers, access points)")
        print("  - f all       (show all devices)")
        print("• Enter 'q' to quit")
        
        user_input = input("\nYour choice: ").strip().lower()
        
        # Handle quit
        if user_input == 'q':
            return None
        
        # Handle instant kick commands
        if user_input.startswith('i ') and gateway_mac:
            try:
                device_id = int(user_input[2:].strip())
                
                # Find device with matching ID in filtered list
                selected_device = None
                for device in filtered_devices:
                    if device['id'] == device_id:
                        selected_device = device
                        break
                
                if selected_device:
                    # Execute instant kick
                    target_mac = selected_device['mac_address']
                    print(f"\n⚡ INSTANT KICK: {selected_device['device_name']} ({target_mac})")
                    
                    deauth = DeauthAttack()
                    success = deauth.instant_kick(target_mac, gateway_mac)
                    
                    if success:
                        print(f"\n✅ Device {selected_device['device_name']} has been kicked!")
                    else:
                        print(f"\n❌ Failed to kick device {selected_device['device_name']}")
                    
                    input("\nPress Enter to continue...")
                    clear_screen()
                    print_banner()
                    continue
                else:
                    print(f"\nInvalid device number: {device_id}")
                    input("Press Enter to continue...")
                    clear_screen()
                    print_banner()
                    continue
                    
            except ValueError:
                print(f"\nInvalid instant kick command: {user_input}")
                print("Use format: i <device_number> (e.g., i 1, i 2)")
                input("Press Enter to continue...")
                clear_screen()
                print_banner()
                continue
        
        # Handle filter commands
        if user_input.startswith('f '):
            filter_type = user_input[2:].strip()
            valid_filters = ['all', 'mobile', 'computer', 'iot', 'gaming', 'network', 'media']
            
            if filter_type in valid_filters:
                current_filter = filter_type
                clear_screen()
                print_banner()
                continue
            else:
                print(f"\nInvalid filter type: {filter_type}")
                print("Valid filters: all, mobile, computer, iot, gaming, network, media")
                input("Press Enter to continue...")
                clear_screen()
                print_banner()
                continue
        
        # Handle regular device selection (with confirmation)
        try:
            device_id = int(user_input)
            
            # Find device with matching ID in filtered list
            selected_device = None
            for device in filtered_devices:
                if device['id'] == device_id:
                    selected_device = device
                    break
            
            if selected_device:
                # Show confirmation for regular kick
                if confirm_device_selection(selected_device):
                    target_mac = selected_device['mac_address']
                    print(f"\nInitiating deauthentication attack on {selected_device['device_name']} ({target_mac})")
                    
                    deauth = DeauthAttack()
                    if gateway_mac:
                        deauth.start_deauth(target_mac, gateway_mac)
                    else:
                        deauth.start_deauth(target_mac)
                    return None
                else:
                    clear_screen()
                    print_banner()
                    continue
            else:
                print(f"\nInvalid device number: {device_id}")
                print(f"Please enter a number between 1 and {len(filtered_devices)}")
                input("Press Enter to continue...")
                clear_screen()
                print_banner()
                continue
                
        except ValueError:
            print(f"\nInvalid input: {user_input}")
            print("Please enter a device number, instant kick command (i <number>), filter command (f <type>), or 'q' to quit.")
            input("Press Enter to continue...")
            clear_screen()
            print_banner()
            continue

def confirm_device_selection(device: Dict) -> bool:
    """
    Show device confirmation dialog.
    
    Args:
        device: Selected device information
        
    Returns:
        True if confirmed, False if cancelled
    """
    print(f"\n══════════════════════════════════════════════════════════════════════")
    print("DEVICE SELECTION CONFIRMATION")
    print("══════════════════════════════════════════════════════════════════════")
    print(f"Device: {device['device_name']}")
    print(f"Vendor: {device['vendor']}")
    print(f"Type: {device['device_type'].title()} {device['type_icon']}")
    print(f"MAC Address: {device['mac_address']}")
    
    if device.get('ip_address'):
        print(f"IP Address: {device['ip_address']}")
    
    confidence = device.get('confidence', 0)
    confidence_text = f"{confidence:.1%}"
    if confidence < 0.7:
        confidence_text += " (Low confidence - device type may be incorrect)"
    print(f"Identification Confidence: {confidence_text}")
    
    print(f"\n⚠️  WARNING: This will disconnect the selected device from the network!")
    print("══════════════════════════════════════════════════════════════════════")
    
    while True:
        confirm = input("\nProceed with deauthentication? (y/n): ").strip().lower()
        if confirm in ['y', 'yes']:
            return True
        elif confirm in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' for yes or 'n' for no.")

def get_available_gateway() -> Optional[str]:
    """
    Automatically detect the gateway/router MAC address from WiFi scan results.
    
    Returns:
        str: Gateway MAC address if found, None otherwise
    """
    try:
        wifi_scanner = WiFiScanner()
        networks = wifi_scanner.scan_networks()
        
        # Look for the strongest signal network (likely the one we're connected to)
        if networks:
            strongest_network = max(networks, key=lambda x: x.get('signal', -100))
            gateway_mac = strongest_network.get('bssid')
            
            # Clean up the MAC address using the helper function
            if gateway_mac:
                return clean_mac_address(gateway_mac)
                    
    except Exception as e:
        print(f"Warning: Could not auto-detect gateway: {str(e)}")
    
    return None

def wifi_ssid_selection_workflow() -> None:
    """
    Scan for available Wi-Fi SSIDs, let user choose one by number,
    and automatically use the correct interface for that network.
    """
    try:
        print("\n══════════════════════════════════════════════════════════════════════")
        print("Wi-Fi SSID Scanner & Interface Selector")
        print("══════════════════════════════════════════════════════════════════════")
        
        # Scan for Wi-Fi networks
        print("🔍 Scanning for available Wi-Fi networks...")
        wifi_scanner = WiFiScanner()
        spinner_event, spinner_thread = start_spinner("Scanning Wi-Fi networks")
        networks = wifi_scanner.scan_networks()
        stop_spinner(spinner_event, spinner_thread)
        
        if not networks:
            print("\n❌ No Wi-Fi networks found.")
            print("Make sure your Wi-Fi adapter is working and try again.")
            return
        
        # Display available networks with numbers
        print(f"\n📡 Found {len(networks)} Wi-Fi networks:")
        print("══════════════════════════════════════════════════════════════════════")
        
        for i, network in enumerate(networks, 1):
            security_icon = "🔒" if network['security'] != "Open" else "🔓"
            signal_bars = "📶" if network['signal'] > -50 else "📶" if network['signal'] > -70 else "📶"
            
            print(f"[{i}] {security_icon} {network['ssid']}")
            print(f"    BSSID: {network['bssid']}")
            print(f"    Signal: {network['signal']}dBm {signal_bars}")
            print(f"    Security: {network['security']}")
            print(f"    Vulnerabilities: {network['vulnerability_status']}")
            print()
        
        # Get user selection
        while True:
            try:
                choice = input(f"Select a Wi-Fi network (1-{len(networks)}) or 'q' to quit: ").strip().lower()
                
                if choice == 'q':
                    print("Wi-Fi selection cancelled.")
                    return
                
                network_index = int(choice) - 1
                if 0 <= network_index < len(networks):
                    selected_network = networks[network_index]
                    break
                else:
                    print(f"Invalid selection. Please enter a number between 1 and {len(networks)}.")
                    
            except ValueError:
                print("Invalid input. Please enter a number or 'q' to quit.")
        
        # Display selected network
        print(f"\n✅ Selected Network: {selected_network['ssid']}")
        print(f"   BSSID: {selected_network['bssid']}")
        print(f"   Security: {selected_network['security']}")
        
        # Auto-detect the correct interface for this network
        print(f"\n🔍 Auto-detecting network interface...")
        
        # Get available interfaces
        from utils import get_available_interfaces, get_interface_info, auto_detect_monitor_interface
        interfaces = get_available_interfaces()
        
        print(f"📡 Available network interfaces:")
        for interface in interfaces:
            info = get_interface_info(interface)
            status_icon = "✅" if info['exists'] else "❌"
            type_info = f"({info['type']})" if info['type'] != 'unknown' else ""
            print(f"   {status_icon} {interface} {type_info}")
        
        # Auto-detect monitor interface
        monitor_interface = auto_detect_monitor_interface()
        monitor_info = get_interface_info(monitor_interface)
        
        print(f"\n🎯 Recommended interface for selected network:")
        print(f"   Interface: {monitor_interface}")
        print(f"   Type: {monitor_info['type']}")
        print(f"   Exists: {'✅ Yes' if monitor_info['exists'] else '❌ No'}")
        print(f"   Monitor Mode: {'✅ Ready' if monitor_info['is_monitor'] else '⚠️  May need setup'}")
        
        # Show network-interface pairing summary
        print(f"\n══════════════════════════════════════════════════════════════════════")
        print("NETWORK-INTERFACE PAIRING SUMMARY")
        print("══════════════════════════════════════════════════════════════════════")
        print(f"Selected Network: {selected_network['ssid']}")
        print(f"Network BSSID:    {selected_network['bssid']}")
        print(f"Recommended Interface: {monitor_interface}")
        print(f"Interface Status: {'Ready' if monitor_info['exists'] else 'Needs Setup'}")
        
        if selected_network['security'] != "Open":
            print(f"Security Type:    {selected_network['security']} 🔒")
        else:
            print(f"Security Type:    Open Network 🔓")
        
        print("══════════════════════════════════════════════════════════════════════")
        
        # Provide next steps information
        print(f"\n💡 Next Steps:")
        print(f"   • Use interface '{monitor_interface}' for operations on '{selected_network['ssid']}'")
        print(f"   • Target BSSID: {selected_network['bssid']}")
        
        if not monitor_info['exists']:
            print(f"   • ⚠️  Interface may need to be set up in monitor mode first")
        
        if selected_network['vulnerability_status'] != "No known vulnerabilities":
            print(f"   • ⚠️  Network vulnerabilities detected: {selected_network['vulnerability_status']}")
        
        print(f"\n✅ Wi-Fi network selection and interface detection completed!")
        
    except KeyboardInterrupt:
        print("\n\nWi-Fi SSID selection cancelled by user.")
    except Exception as e:
        print(f"\nError during Wi-Fi SSID selection: {str(e)}")

def scan_and_kick_workflow() -> None:
    """
    Main integrated workflow for scanning and kicking devices with instant kick option.
    """
    try:
        # Perform full network scan
        print("Starting comprehensive network scan...")
        devices = scan_network()
        
        if not devices:
            print("\n══════════════════════════════════════════════════════════════════════")
            print("No devices found on the network.")
            print("Make sure you're connected to a network and try again.")
            print("══════════════════════════════════════════════════════════════════════")
            return
        
        # Filter out WiFi networks (only show actual devices for kicking)
        kickable_devices = [d for d in devices if d.get('type') != 'wifi' or d.get('device_type') != 'network']
        
        if not kickable_devices:
            print("\n══════════════════════════════════════════════════════════════════════")
            print("No kickable devices found.")
            print("Only WiFi access points were detected, which cannot be kicked.")
            print("══════════════════════════════════════════════════════════════════════")
            return
        
        # Try to auto-detect gateway
        gateway_mac = get_available_gateway()
        
        clear_screen()
        print_banner()
        
        # Get device selection with instant kick option
        get_device_selection_with_instant_kick(kickable_devices, gateway_mac)
            
    except KeyboardInterrupt:
        print("\n\nScan and kick workflow cancelled by user.")
    except Exception as e:
        print(f"\nError during scan and kick workflow: {str(e)}")

def manual_deauth_workflow() -> None:
    """
    Manual deauthentication workflow with interface auto-detection.
    Allows user to manually enter MAC address with auto-detected interface.
    """
    try:
        print("\n══════════════════════════════════════════════════════════════════════")
        print("MANUAL DEAUTHENTICATION ATTACK")
        print("══════════════════════════════════════════════════════════════════════")
        
        # Auto-detect network interface
        print("🔍 Auto-detecting network interface...")
        detected_interface = auto_detect_monitor_interface()
        interface_info = get_interface_info(detected_interface)
        
        print(f"\n📡 Interface Detection Results:")
        print(f"   Detected Interface: {detected_interface}")
        print(f"   Interface Type: {interface_info['type']}")
        print(f"   Interface Exists: {'✅ Yes' if interface_info['exists'] else '❌ No'}")
        
        if interface_info['is_monitor']:
            print(f"   Monitor Mode: ✅ Ready")
        else:
            print(f"   Monitor Mode: ⚠️  Interface may need to be set to monitor mode")
        
        # Auto-detect gateway MAC
        print(f"\n🔍 Auto-detecting gateway MAC address...")
        gateway_mac = get_available_gateway()
        
        if gateway_mac:
            print(f"   Gateway MAC: ✅ {gateway_mac}")
        else:
            print(f"   Gateway MAC: ❌ Could not auto-detect")
        
        print(f"\n══════════════════════════════════════════════════════════════════════")
        
        # Get target MAC address from user
        while True:
            target_mac = input("\nEnter target device MAC address (XX:XX:XX:XX:XX:XX): ").strip()
            
            if not target_mac:
                print("MAC address cannot be empty. Please try again.")
                continue
            
            # Validate MAC address format
            deauth = DeauthAttack()
            if not deauth._validate_mac_address(target_mac):
                print("Invalid MAC address format. Please use XX:XX:XX:XX:XX:XX format.")
                continue
            
            break
        
        # Get gateway MAC if not auto-detected
        if not gateway_mac:
            while True:
                gateway_mac = input("\nEnter gateway/router MAC address (XX:XX:XX:XX:XX:XX): ").strip()
                
                if not gateway_mac:
                    print("Gateway MAC address cannot be empty. Please try again.")
                    continue
                
                if not deauth._validate_mac_address(gateway_mac):
                    print("Invalid MAC address format. Please use XX:XX:XX:XX:XX:XX format.")
                    continue
                
                break
        
        # Allow user to override auto-detected interface if needed
        print(f"\nAuto-detected interface: {detected_interface}")
        override_interface = input("Press Enter to use auto-detected interface, or type a different interface name: ").strip()
        
        if override_interface:
            detected_interface = override_interface
            print(f"Using custom interface: {detected_interface}")
        else:
            print(f"Using auto-detected interface: {detected_interface}")
        
        # Show attack summary
        print(f"\n══════════════════════════════════════════════════════════════════════")
        print("ATTACK SUMMARY")
        print("══════════════════════════════════════════════════════════════════════")
        print(f"Target MAC:    {target_mac}")
        print(f"Gateway MAC:   {gateway_mac}")
        print(f"Interface:     {detected_interface}")
        print(f"Attack Type:   Deauthentication")
        print("══════════════════════════════════════════════════════════════════════")
        
        # Final confirmation
        while True:
            confirm = input("\n⚠️  Proceed with deauthentication attack? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                break
            elif confirm in ['n', 'no']:
                print("Attack cancelled by user.")
                return
            else:
                print("Please enter 'y' for yes or 'n' for no.")
        
        # Execute the attack
        print(f"\n🚀 Starting deauthentication attack...")
        print(f"Target: {target_mac}")
        print(f"Gateway: {gateway_mac}")
        print(f"Interface: {detected_interface}")
        
        deauth = DeauthAttack()
        deauth.start_deauth(target_mac, gateway_mac, detected_interface)
        
    except KeyboardInterrupt:
        print("\n\nManual deauth workflow cancelled by user.")
    except Exception as e:
        print(f"\nError during manual deauth workflow: {str(e)}")

if __name__ == "__main__":
    while True:
        clear_screen()
        print_banner()
        choice = print_menu()
        
        if choice == '1':
            # WiFi Networks Only
            try:
                wifi_scanner = WiFiScanner()
                networks = [d for d in scan_network() if d.get('type') == 'wifi']
                clear_screen()
                print_banner()
                display_wifi_networks(networks)
            except Exception as e:
                print(f"\nError scanning WiFi networks: {str(e)}")
        
        elif choice == '2':
            # Local Network Devices Only
            try:
                spinner_event, spinner_thread = start_spinner("Scanning local network")
                devices = scan_network()
                stop_spinner(spinner_event, spinner_thread)
                # Filter network devices and remove any None values
                network_devices = [d for d in devices if d and d.get('type') == 'device']
                clear_screen()
                print_banner()
                display_local_devices(network_devices)
            except Exception as e:
                if 'spinner' in locals():
                    stop_spinner(spinner_event, spinner_thread)
                print(f"\nError scanning local network: {str(e)}")
        
        elif choice == '3':
            # Full Network Scan
            try:
                spinner_event, spinner_thread = start_spinner("Performing full network scan")
                devices = scan_network()
                stop_spinner(spinner_event, spinner_thread)
                
                # Filter devices by type and remove any None values
                wifi_devices = [d for d in devices if d and d.get('type') == 'wifi']
                network_devices = [d for d in devices if d and d.get('type') == 'device']
                
                clear_screen()
                print_banner()
                if wifi_devices:
                    display_wifi_networks(wifi_devices)
                if network_devices:
                    display_local_devices(network_devices)
            except Exception as e:
                if 'spinner' in locals():
                    stop_spinner(spinner_event, spinner_thread)
                print(f"\nError during full network scan: {str(e)}")
        
        elif choice == '4':
            # Wi-Fi SSID selection with auto-interface detection
            try:
                wifi_ssid_selection_workflow()
            except Exception as e:
                print(f"\nError during Wi-Fi SSID selection: {str(e)}")
        
        elif choice == '5':
            # Scan and kick workflow (smart selection)
            try:
                scan_and_kick_workflow()
            except Exception as e:
                print(f"\nError during scan and kick workflow: {str(e)}")
        
        elif choice == '6':
            print("\nExiting Network Scanner. Goodbye!")
            break
        
        else:
            print("\nInvalid choice. Please enter a number between 1 and 6.")
        
        input("\nPress Enter to continue...")
        clear_screen()