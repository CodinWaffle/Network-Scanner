# Network-Scanner



```
/docs
├── overview.md
├── architecture.md
├── usage-guide.md
├── components.md
├── filtering.md
├── developer-guide.md
└── troubleshooting.md
```

---

### 🔹 `docs/overview.md`

```markdown
# Overview

The Enhanced Network Scanner is a Python-based toolkit for detecting, classifying, and interacting with devices on a local or WiFi network. It features:

- Smart device type detection (phones, routers, IoT, etc.)
- Vendor lookup using MAC OUI
- Categorized selection interface
- Integrated deauthentication attack (Linux/WSL)

This tool is ideal for ethical hackers, penetration testers, or anyone interested in network visibility and control.
```

---

### 🔹 `docs/architecture.md`

````markdown
# Architecture Overview

## Workflow

1. Full network scan via Scapy.
2. Each device’s MAC is matched to vendor using OUI.
3. Device is categorized using known patterns (e.g., Apple = Phone or Computer).
4. Friendly display with filters for easy selection.
5. Deauthentication attack is initiated on chosen device.

## Components

- `scanner.py`: Main interface + scanner logic
- `device_identifier.py`: Classification logic (MAC + pattern matching)
- `utils.py`: OUI database loading and helpers

## Architecture Flow

```mermaid
graph TD
    Scan --> MatchMAC --> Classify --> Display --> Filter/Select --> Deauth
````

````

---

### 🔹 `docs/usage-guide.md`

```markdown
# Usage Guide

## Requirements

- Python 3.8+
- Linux or WSL
- Monitor-mode WiFi adapter
- Install: `pip install -r requirements.txt`

## Running

```bash
python3 main.py
````

## Main Menu

```
1. Scan WiFi Networks
2. Scan Local Devices
3. Full Scan
4. Deauth by MAC
5. Smart Scan + Kick ← Recommended
6. Exit
```

## Example

```
📱 MOBILE DEVICES
[1] iPhone 14 | MAC: AA:BB:CC:DD:EE:FF

🌐 NETWORK DEVICES
[2] TP-Link Router | MAC: 44:55:66:77:88:99

Enter '1' to deauth, 'f iot' to filter, or 'q' to quit.
```

````

---

### 🔹 `docs/components.md`

```markdown
# Component Details

## Device Info Object

```python
device_info = {
  "mac_address": "...",
  "ip_address": "...",
  "device_type": "phone",
  "vendor": "Apple",
  "device_name": "iPhone 14",
  "confidence": 0.9
}
````

## OUI Database

```python
OUI_DATABASE = {
  "00:03:93": {"vendor": "Apple", "type_hint": "mobile"},
  "B8:27:EB": {"vendor": "Raspberry Pi", "type_hint": "iot"},
}
```

## Pattern Matching

```python
DEVICE_PATTERNS = {
  "apple": {
    "mobile_patterns": ["iPhone", "iPad"],
    "confidence_boost": 0.2
  }
}
```

````

---

### 🔹 `docs/filtering.md`

```markdown
# Filtering & Selection

Users can filter displayed devices by type:

- `f phones`
- `f computers`
- `f iot`
- `f gaming`
- `f network`
- `f all`

After filtering, select the device number to initiate deauth.

Invalid input or unknown device types are handled gracefully.
````

---

### 🔹 `docs/developer-guide.md`

```markdown
# Developer Guide

### Key Functions

- `identify_and_categorize_devices(devices)`
- `display_categorized_device_menu(devices)`
- `filter_devices_by_type(devices)`
- `get_device_selection_with_filters(devices)`

### To Extend:

- Add more OUI entries in `OUI_DATABASE`
- Update `DEVICE_PATTERNS` with more vendors
- Modify `device_identifier.py` to improve pattern matching
```

---

### 🔹 `docs/troubleshooting.md`

```markdown
# Troubleshooting

### ❓ "Deauth not working"

- Make sure you're using Linux or WSL
- WiFi adapter must support monitor mode
- Run script with `sudo` if needed

### ⚠️ "Unknown Device Type"

- Vendor may be missing from database
- Falls back to 'Unknown' category
- Consider updating `OUI_DATABASE`

### 🔁 MAC Conflicts

- Tool checks for duplicates in scan results
- Assigns unique device IDs for selection
```

---

