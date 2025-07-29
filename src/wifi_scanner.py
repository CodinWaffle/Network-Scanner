import pywifi
from pywifi import const
import time
from typing import List, Dict

class WiFiScanner:
    def __init__(self):
        self.wifi = pywifi.PyWiFi()
        interfaces = self.wifi.interfaces()
        if not interfaces:
            raise RuntimeError("No wireless interfaces found")
        print(f"Found {len(interfaces)} wireless interfaces")
        self.iface = interfaces[0]  # Get the first wireless interface
        print(f"Using interface: {self.iface.name()}")

    def scan_networks(self) -> List[Dict]:
        """
        Scan for available Wi-Fi networks and return their details
        """
        self.iface.scan()  # Trigger scanning
        time.sleep(2)  # Wait for scan to complete
        
        networks = []
        scan_results = self.iface.scan_results()
        
        for result in scan_results:
            network = {
                'ssid': result.ssid,
                'bssid': result.bssid,
                'signal': result.signal,
                'security': self._get_security_type(result),
                'auth': self._get_auth_type(result),
                'vulnerability_status': self._check_security_vulnerabilities(result)
            }
            networks.append(network)
        
        return networks

    def _get_security_type(self, result) -> str:
        """
        Determine the security type of the network
        """
        try:
            if not hasattr(result, 'akm') or not result.akm:
                return "Open"
            
            # Check if akm contains any authentication method
            if len(result.akm) > 0:
                return "WPA/WPA2"
            
            return "Unknown"
        except Exception:
            return "Unknown"

    def _get_auth_type(self, result) -> str:
        """
        Get the authentication type of the network
        """
        try:
            if hasattr(result, 'auth_alg'):
                return "Authenticated"
            return "Open"
        except Exception:
            return "Unknown"

    def _check_security_vulnerabilities(self, result) -> str:
        """
        Check for known security vulnerabilities
        """
        security = self._get_security_type(result)
        vulnerabilities = []

        if security == "Open":
            vulnerabilities.append("Unencrypted network")
        elif security == "Unknown":
            vulnerabilities.append("Security type could not be determined")

        return ", ".join(vulnerabilities) if vulnerabilities else "No known vulnerabilities"

    def get_connected_clients(self, interface: str = None) -> List[Dict]:
        """
        Get list of clients connected to the network
        Requires elevated privileges
        """
        import scapy.all as scapy
        
        if not interface:
            interface = self.iface.name()
        
        # Send deauth packet to force devices to reconnect (requires root/admin)
        deauth = scapy.RadioTap() / scapy.Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff")
        scapy.sendp(deauth, iface=interface, count=1, verbose=False)
        
        # Capture probe responses and beacon frames
        clients = set()
        def packet_handler(pkt):
            if pkt.haslayer(scapy.Dot11):
                if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                    if pkt.addr2 and pkt.addr2 not in clients:
                        clients.add({
                            'mac': pkt.addr2,
                            'type': 'AP',
                            'ssid': pkt.info.decode() if pkt.info else 'Hidden'
                        })
                elif pkt.type == 2:  # Data frame
                    if pkt.addr1 and pkt.addr1 not in clients:
                        clients.add({
                            'mac': pkt.addr1,
                            'type': 'Client',
                            'connected_to': pkt.addr2
                        })
        
        # Sniff for 10 seconds
        scapy.sniff(iface=interface, prn=packet_handler, timeout=10)
        return list(clients)
