import re
from typing import Dict, List, Optional, Tuple

class DeviceIdentifier:
    """
    Enhanced device identifier with automatic device type detection
    based on MAC address OUI lookup and behavioral patterns.
    """
    
    def __init__(self):
        """Initialize the DeviceIdentifier with OUI database and patterns."""
        self.oui_database = self._load_oui_database()
        self.device_patterns = self._load_device_patterns()
        self.device_type_icons = {
            'mobile': '📱',
            'computer': '💻',
            'iot': '🏠',
            'gaming': '🎮',
            'network': '🌐',
            'media': '📺',
            'unknown': '❓'
        }
    
    def _load_oui_database(self) -> Dict[str, Dict[str, str]]:
        """Load the OUI (Organizationally Unique Identifier) database."""
        return {
            # Apple devices
            "00:03:93": {"vendor": "Apple", "type_hint": "mobile"},
            "00:05:02": {"vendor": "Apple", "type_hint": "computer"},
            "00:0A:95": {"vendor": "Apple", "type_hint": "mobile"},
            "00:14:51": {"vendor": "Apple", "type_hint": "computer"},
            "00:16:CB": {"vendor": "Apple", "type_hint": "mobile"},
            "00:17:F2": {"vendor": "Apple", "type_hint": "computer"},
            "00:19:E3": {"vendor": "Apple", "type_hint": "mobile"},
            "00:1B:63": {"vendor": "Apple", "type_hint": "computer"},
            "00:1E:C2": {"vendor": "Apple", "type_hint": "mobile"},
            "00:21:E9": {"vendor": "Apple", "type_hint": "computer"},
            "00:23:12": {"vendor": "Apple", "type_hint": "mobile"},
            "00:23:DF": {"vendor": "Apple", "type_hint": "computer"},
            "00:25:00": {"vendor": "Apple", "type_hint": "mobile"},
            "00:25:4B": {"vendor": "Apple", "type_hint": "computer"},
            "00:26:08": {"vendor": "Apple", "type_hint": "mobile"},
            "00:26:4A": {"vendor": "Apple", "type_hint": "computer"},
            "00:26:B0": {"vendor": "Apple", "type_hint": "mobile"},
            "00:26:BB": {"vendor": "Apple", "type_hint": "computer"},
            
            # Samsung devices
            "00:07:AB": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:12:FB": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:15:99": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:16:32": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:17:C9": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:1A:8A": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:1D:25": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:1E:7D": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:21:19": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:23:39": {"vendor": "Samsung", "type_hint": "mobile"},
            "00:26:37": {"vendor": "Samsung", "type_hint": "mobile"},
            "34:23:87": {"vendor": "Samsung", "type_hint": "iot"},
            "40:4E:36": {"vendor": "Samsung", "type_hint": "iot"},
            
            # Intel devices (usually computers)
            "00:03:47": {"vendor": "Intel", "type_hint": "computer"},
            "00:04:23": {"vendor": "Intel", "type_hint": "computer"},
            "00:07:E9": {"vendor": "Intel", "type_hint": "computer"},
            "00:0E:0C": {"vendor": "Intel", "type_hint": "computer"},
            "00:13:02": {"vendor": "Intel", "type_hint": "computer"},
            "00:13:CE": {"vendor": "Intel", "type_hint": "computer"},
            "00:15:00": {"vendor": "Intel", "type_hint": "computer"},
            "00:16:E3": {"vendor": "Intel", "type_hint": "computer"},
            "00:19:D1": {"vendor": "Intel", "type_hint": "computer"},
            "00:1B:21": {"vendor": "Intel", "type_hint": "computer"},
            "00:1E:64": {"vendor": "Intel", "type_hint": "computer"},
            "00:21:6A": {"vendor": "Intel", "type_hint": "computer"},
            "00:24:D7": {"vendor": "Intel", "type_hint": "computer"},
            
            # Raspberry Pi (IoT/Computer)
            "B8:27:EB": {"vendor": "Raspberry Pi Foundation", "type_hint": "iot"},
            "DC:A6:32": {"vendor": "Raspberry Pi Foundation", "type_hint": "iot"},
            "E4:5F:01": {"vendor": "Raspberry Pi Foundation", "type_hint": "iot"},
            
            # TP-Link (Network equipment)
            "14:CC:20": {"vendor": "TP-Link", "type_hint": "network"},
            "50:C7:BF": {"vendor": "TP-Link", "type_hint": "network"},
            "A4:2B:B0": {"vendor": "TP-Link", "type_hint": "network"},
            "C4:E9:84": {"vendor": "TP-Link", "type_hint": "network"},
            "F4:F2:6D": {"vendor": "TP-Link", "type_hint": "network"},
            
            # Netgear (Network equipment)
            "00:09:5B": {"vendor": "Netgear", "type_hint": "network"},
            "00:0F:B5": {"vendor": "Netgear", "type_hint": "network"},
            "00:14:6C": {"vendor": "Netgear", "type_hint": "network"},
            "00:18:4D": {"vendor": "Netgear", "type_hint": "network"},
            "00:1B:2F": {"vendor": "Netgear", "type_hint": "network"},
            "00:1E:2A": {"vendor": "Netgear", "type_hint": "network"},
            "00:22:3F": {"vendor": "Netgear", "type_hint": "network"},
            "00:24:B2": {"vendor": "Netgear", "type_hint": "network"},
            "00:26:F2": {"vendor": "Netgear", "type_hint": "network"},
            
            # Sony (Gaming/Media)
            "00:04:1F": {"vendor": "Sony", "type_hint": "gaming"},
            "00:09:BF": {"vendor": "Sony", "type_hint": "gaming"},
            "00:0D:F0": {"vendor": "Sony", "type_hint": "gaming"},
            "00:13:A9": {"vendor": "Sony", "type_hint": "gaming"},
            "00:16:FE": {"vendor": "Sony", "type_hint": "gaming"},
            "00:19:C5": {"vendor": "Sony", "type_hint": "gaming"},
            "00:1B:FB": {"vendor": "Sony", "type_hint": "gaming"},
            "00:1D:BA": {"vendor": "Sony", "type_hint": "gaming"},
            "00:1F:E4": {"vendor": "Sony", "type_hint": "gaming"},
            "00:22:CF": {"vendor": "Sony", "type_hint": "gaming"},
            
            # Microsoft (Gaming/Computer)
            "00:50:F2": {"vendor": "Microsoft", "type_hint": "gaming"},
            "00:15:5D": {"vendor": "Microsoft", "type_hint": "computer"},
            "7C:ED:8D": {"vendor": "Microsoft", "type_hint": "gaming"},
            
            # Amazon (IoT)
            "00:FC:8B": {"vendor": "Amazon", "type_hint": "iot"},
            "44:65:0D": {"vendor": "Amazon", "type_hint": "iot"},
            "50:DC:E7": {"vendor": "Amazon", "type_hint": "iot"},
            "74:C2:46": {"vendor": "Amazon", "type_hint": "iot"},
            "84:D6:D0": {"vendor": "Amazon", "type_hint": "iot"},
            "AC:63:BE": {"vendor": "Amazon", "type_hint": "iot"},
            "F0:27:2D": {"vendor": "Amazon", "type_hint": "iot"},
            
            # Google (IoT/Mobile)
            "00:1A:11": {"vendor": "Google", "type_hint": "iot"},
            "DA:A1:19": {"vendor": "Google", "type_hint": "iot"},
            "F4:F5:D8": {"vendor": "Google", "type_hint": "iot"},
            "6C:AD:F8": {"vendor": "Google", "type_hint": "mobile"},
            
            # Philips (IoT)
            "00:17:88": {"vendor": "Philips", "type_hint": "iot"},
            "EC:B5:FA": {"vendor": "Philips", "type_hint": "iot"},
        }
    
    def _load_device_patterns(self) -> Dict[str, Dict[str, any]]:
        """Load device identification patterns."""
        return {
            "apple": {
                "mobile_keywords": ["iphone", "ipad", "ipod", "mobile"],
                "computer_keywords": ["macbook", "imac", "mac", "laptop", "desktop"],
                "confidence_boost": 0.2
            },
            "samsung": {
                "mobile_keywords": ["galaxy", "note", "phone", "tablet"],
                "iot_keywords": ["smart", "tv", "refrigerator", "washer"],
                "confidence_boost": 0.15
            },
            "intel": {
                "computer_keywords": ["wireless", "wifi", "ethernet", "network"],
                "confidence_boost": 0.1
            },
            "sony": {
                "gaming_keywords": ["playstation", "ps4", "ps5", "console"],
                "media_keywords": ["tv", "bravia", "media"],
                "confidence_boost": 0.15
            },
            "microsoft": {
                "gaming_keywords": ["xbox", "console"],
                "computer_keywords": ["surface", "laptop"],
                "confidence_boost": 0.15
            },
            "raspberry": {
                "iot_keywords": ["pi", "raspberry", "iot", "sensor"],
                "computer_keywords": ["desktop", "server"],
                "confidence_boost": 0.2
            }
        }
    
    def get_vendor_from_mac(self, mac_address: str) -> Tuple[str, str]:
        """
        Get vendor information from MAC address OUI.
        
        Args:
            mac_address: MAC address in format XX:XX:XX:XX:XX:XX
            
        Returns:
            Tuple of (vendor_name, type_hint)
        """
        if not mac_address or len(mac_address) < 8:
            return "Unknown", "unknown"
        
        # Extract OUI (first 3 octets)
        oui = mac_address[:8].upper()
        
        if oui in self.oui_database:
            vendor_info = self.oui_database[oui]
            return vendor_info["vendor"], vendor_info["type_hint"]
        
        return "Unknown", "unknown"
    
    def classify_device_type(self, vendor: str, type_hint: str, additional_info: Optional[Dict] = None) -> Tuple[str, float]:
        """
        Classify device type based on vendor and additional information.
        
        Args:
            vendor: Device vendor name
            type_hint: Initial type hint from OUI lookup
            additional_info: Additional device information (hostname, etc.)
            
        Returns:
            Tuple of (device_type, confidence_score)
        """
        confidence = 0.5  # Base confidence
        device_type = type_hint if type_hint != "unknown" else "unknown"
        
        vendor_lower = vendor.lower()
        
        # Apply vendor-specific patterns
        if vendor_lower in self.device_patterns:
            patterns = self.device_patterns[vendor_lower]
            confidence += patterns.get("confidence_boost", 0)
            
            # Check additional info for keywords
            if additional_info:
                info_text = " ".join(str(v).lower() for v in additional_info.values())
                
                for category, keywords in patterns.items():
                    if category.endswith("_keywords"):
                        category_type = category.replace("_keywords", "")
                        if any(keyword in info_text for keyword in keywords):
                            device_type = category_type
                            confidence += 0.2
                            break
        
        # Apply general classification rules
        if device_type == "unknown":
            if "router" in vendor_lower or "netgear" in vendor_lower or "linksys" in vendor_lower:
                device_type = "network"
                confidence += 0.3
            elif "tv" in vendor_lower or "samsung" in vendor_lower:
                device_type = "iot"
                confidence += 0.2
        
        # Ensure confidence is within bounds
        confidence = min(1.0, max(0.1, confidence))
        
        return device_type, confidence
    
    def generate_friendly_name(self, vendor: str, device_type: str, mac_address: str) -> str:
        """
        Generate a friendly device name.
        
        Args:
            vendor: Device vendor
            device_type: Classified device type
            mac_address: Device MAC address
            
        Returns:
            Friendly device name
        """
        type_names = {
            "mobile": ["iPhone", "Galaxy Phone", "Android Phone", "Tablet"],
            "computer": ["MacBook", "Laptop", "Desktop", "Workstation"],
            "iot": ["Smart Device", "IoT Device", "Smart Home", "Sensor"],
            "gaming": ["PlayStation", "Xbox", "Gaming Console", "Nintendo"],
            "network": ["Router", "Access Point", "Switch", "Modem"],
            "media": ["Smart TV", "Streaming Device", "Media Player", "Set-top Box"],
            "unknown": ["Unknown Device", "Network Device", "Connected Device"]
        }
        
        vendor_specific_names = {
            "Apple": {
                "mobile": ["iPhone", "iPad", "iPod Touch"],
                "computer": ["MacBook Pro", "MacBook Air", "iMac", "Mac Mini"]
            },
            "Samsung": {
                "mobile": ["Galaxy Phone", "Galaxy Tablet", "Note"],
                "iot": ["Smart TV", "Smart Refrigerator", "Smart Washer"]
            },
            "Sony": {
                "gaming": ["PlayStation 5", "PlayStation 4", "PS Console"],
                "media": ["Bravia TV", "Sony TV"]
            },
            "Microsoft": {
                "gaming": ["Xbox Series X", "Xbox One", "Xbox Console"],
                "computer": ["Surface Laptop", "Surface Pro"]
            },
            "Google": {
                "iot": ["Nest Hub", "Chromecast", "Google Home"],
                "mobile": ["Pixel Phone", "Android Device"]
            }
        }
        
        # Try vendor-specific naming first
        if vendor in vendor_specific_names and device_type in vendor_specific_names[vendor]:
            names = vendor_specific_names[vendor][device_type]
            return names[0]  # Return the first (most common) name
        
        # Fall back to generic naming
        if device_type in type_names:
            return type_names[device_type][0]
        
        return f"{vendor} Device"
    
    def identify_device_type(self, mac_address: str, ip_address: Optional[str] = None, 
                           hostname: Optional[str] = None) -> Dict[str, any]:
        """
        Main function to identify device type and generate comprehensive device info.
        
        Args:
            mac_address: Device MAC address
            ip_address: Device IP address (optional)
            hostname: Device hostname (optional)
            
        Returns:
            Dictionary with device identification results
        """
        # Get vendor information
        vendor, type_hint = self.get_vendor_from_mac(mac_address)
        
        # Prepare additional info
        additional_info = {}
        if hostname:
            additional_info["hostname"] = hostname
        if ip_address:
            additional_info["ip"] = ip_address
        
        # Classify device type
        device_type, confidence = self.classify_device_type(vendor, type_hint, additional_info)
        
        # Generate friendly name
        friendly_name = self.generate_friendly_name(vendor, device_type, mac_address)
        
        return {
            "vendor": vendor,
            "device_type": device_type,
            "device_name": friendly_name,
            "confidence": confidence,
            "type_icon": self.device_type_icons.get(device_type, "❓"),
            "classification_source": "oui_lookup" if vendor != "Unknown" else "pattern_matching"
        }
    
    def get_device_category_display_name(self, device_type: str) -> str:
        """Get display name for device category."""
        category_names = {
            "mobile": "MOBILE DEVICES",
            "computer": "COMPUTERS", 
            "iot": "IOT DEVICES",
            "gaming": "GAMING DEVICES",
            "network": "NETWORK EQUIPMENT",
            "media": "MEDIA DEVICES",
            "unknown": "UNKNOWN DEVICES"
        }
        return category_names.get(device_type, "OTHER DEVICES")
    
    def filter_devices_by_type(self, devices: List[Dict], device_type: str) -> List[Dict]:
        """
        Filter devices by type.
        
        Args:
            devices: List of device dictionaries
            device_type: Type to filter by
            
        Returns:
            Filtered list of devices
        """
        if device_type == "all":
            return devices
        
        return [device for device in devices if device.get("device_type") == device_type]