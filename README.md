

---

# Network Scanner Documentation

A simple Python-based tool for scanning devices on a network and identifying their types (phones, computers, IoT, etc.). It includes a smart menu for selecting and deauthing devices.

---

## 📌 Features

* Scan WiFi networks and connected devices
* Auto-detect device type and vendor
* Group devices by category (mobile, router, etc.)
* Filter device list by type
* Deauthenticate devices (Linux/WSL only)

---

## Scan Options

```
1. WiFi Network Scan  
2. Local Devices Scan  
3. Full Network Scan  
4. WiFi SSID Scan  
5. Smart Scan & Kick  
6. Exit
```

---

## 🛠 Requirements

* Python 3.8+
* Linux or WSL (for deauth)
* Monitor-mode WiFi adapter
* Run: `pip install -r requirements.txt`

---

##  How to Use

1. Run the tool:

   ```
   python3 main.py
   ```
2. Choose an option from the menu.
3. For Option 5 (Smart Scan & Kick):

   * The tool scans devices
   * Shows them grouped by type
   * You can filter by type or pick a device number
   * Confirm, then deauth is executed

---

## Device Info Format

Each device contains:

```python
{
  'ip_address': '192.168.1.100',
  'mac_address': 'AA:BB:CC:DD:EE:FF',
  'device_name': 'iPhone 14',
  'vendor': 'Apple',
  'device_type': 'phone',
  'confidence': 0.92
}
```

---

## Device Types

* 📱 Phones
* 💻 Computers
* 🏠 IoT Devices
* 🌐 Routers
* 🎮 Gaming Devices
* 📺 Media Devices
* ❓ Unknown

---

## Filtering Commands

During device selection, you can type:

* `f phones` — show only phones
* `f computers` — show computers
* `f iot` — show IoT
* `f all` — show everything
* `q` — quit

---

## Main Files

* `main.py` — Entry point
* `scanner.py` — Handles scans and menus
* `device_identifier.py` — Detects device type/vendor
* `utils.py` — Loads OUI/vendor data

---

## ❗ Notes

* Deauthentication only works on **Linux/WSL with monitor mode**
* Unknown devices are shown as "Unknown"
* Make sure to run as root or with `sudo` if needed

---

## 📜 License

MIT License – For educational and authorized use only.

---

