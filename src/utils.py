import socket
import subprocess
import re
import os
from typing import Optional, List

def get_mac_address():
    # Function to retrieve the MAC address of the local machine
    # This is a placeholder as we don't need it for scanning
    pass

def get_ip_range():
    """Get the IP range of the current network in CIDR notation (e.g., '192.168.1.0/24')"""
    try:
        # Get the hostname and IP address
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        
        # Most home networks use /24 subnet
        ip_parts = ip_address.split('.')
        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        return network
    except:
        # Fallback to local network if we can't determine the actual network
        return "192.168.1.0/24"

def get_available_interfaces() -> List[str]:
    """
    Get list of available network interfaces on the system.
    
    Returns:
        List[str]: List of available network interface names
    """
    interfaces = []
    
    try:
        if os.name == 'nt':  # Windows
            # Use netsh to get interface names
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Connected' in line or 'Enabled' in line:
                        # Extract interface name (usually the last part)
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            interface_name = ' '.join(parts[3:])
                            # Convert to common naming convention
                            if 'Wi-Fi' in interface_name or 'Wireless' in interface_name:
                                interfaces.append('wlan0')
                            elif 'Ethernet' in interface_name:
                                interfaces.append('eth0')
        else:  # Linux/Unix
            # Use ip command or ifconfig
            try:
                result = subprocess.run(['ip', 'link', 'show'],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        match = re.search(r'^\d+:\s+(\w+):', line)
                        if match:
                            interface = match.group(1)
                            if interface != 'lo':  # Skip loopback
                                interfaces.append(interface)
            except FileNotFoundError:
                # Fallback to ifconfig
                try:
                    result = subprocess.run(['ifconfig'],
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if line and not line.startswith(' ') and not line.startswith('\t'):
                                interface = line.split(':')[0].strip()
                                if interface != 'lo':  # Skip loopback
                                    interfaces.append(interface)
                except FileNotFoundError:
                    pass
    except Exception as e:
        print(f"Warning: Could not detect interfaces: {str(e)}")
    
    # Add common interface names as fallback
    if not interfaces:
        interfaces = ['wlan0', 'wlan1', 'eth0', 'eth1']
    
    return interfaces

def auto_detect_monitor_interface() -> Optional[str]:
    """
    Automatically detect the best network interface for monitor mode.
    
    Returns:
        Optional[str]: Interface name with 'mon' suffix if found, None otherwise
    """
    try:
        # Get available interfaces
        interfaces = get_available_interfaces()
        
        # Look for wireless interfaces first
        wireless_interfaces = []
        for interface in interfaces:
            if 'wlan' in interface.lower() or 'wifi' in interface.lower():
                wireless_interfaces.append(interface)
        
        # If no wireless interfaces found, use the first available interface
        if not wireless_interfaces:
            wireless_interfaces = interfaces[:1]  # Take first interface
        
        # Try to find an interface that's already in monitor mode
        for interface in wireless_interfaces:
            monitor_interface = f"{interface}mon"
            if check_interface_exists(monitor_interface):
                return monitor_interface
        
        # Return the first wireless interface with 'mon' suffix
        if wireless_interfaces:
            return f"{wireless_interfaces[0]}mon"
            
    except Exception as e:
        print(f"Warning: Could not auto-detect monitor interface: {str(e)}")
    
    # Fallback to common monitor interface names
    common_monitor_interfaces = ['wlan0mon', 'wlan1mon', 'wlp2s0mon', 'wlp3s0mon']
    for interface in common_monitor_interfaces:
        if check_interface_exists(interface):
            return interface
    
    # Final fallback
    return 'wlan0mon'

def check_interface_exists(interface: str) -> bool:
    """
    Check if a network interface exists on the system.
    
    Args:
        interface: Interface name to check
        
    Returns:
        bool: True if interface exists, False otherwise
    """
    try:
        if os.name == 'nt':  # Windows
            # On Windows, we can't easily check for monitor mode interfaces
            # Return True for common patterns
            return 'mon' in interface.lower()
        else:  # Linux/Unix
            # Check if interface exists in /sys/class/net/
            return os.path.exists(f"/sys/class/net/{interface}")
    except Exception:
        return False

def get_interface_info(interface: str) -> dict:
    """
    Get information about a network interface.
    
    Args:
        interface: Interface name
        
    Returns:
        dict: Interface information including status and type
    """
    info = {
        'name': interface,
        'exists': False,
        'is_up': False,
        'is_monitor': False,
        'type': 'unknown'
    }
    
    try:
        info['exists'] = check_interface_exists(interface)
        
        if info['exists']:
            # Determine interface type
            if 'wlan' in interface.lower() or 'wifi' in interface.lower():
                info['type'] = 'wireless'
            elif 'eth' in interface.lower():
                info['type'] = 'ethernet'
            elif 'mon' in interface.lower():
                info['is_monitor'] = True
                info['type'] = 'monitor'
            
            # Check if interface is up (Linux/Unix only)
            if os.name != 'nt':
                try:
                    result = subprocess.run(['ip', 'link', 'show', interface],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        info['is_up'] = 'UP' in result.stdout
                except Exception:
                    pass
    except Exception as e:
        print(f"Warning: Could not get interface info for {interface}: {str(e)}")
    
    return info
