# Network Scanner

This project is a network scanner that identifies devices connected to a local network.
<img width="834" height="340" alt="Image" src="https://github.com/user-attachments/assets/4f670b52-0ca0-4752-9a89-1c27002cac23" />

## Features

- Scans the local network for connected devices.
- Identifies the type of each device (computer or phone).
- Retrieves the brand of each device based on its MAC address.

## Project Structure

```
network-scanner
├── src
│   ├── scanner.py          - Main entry point for the network scanner
│   ├── device_identifier.py - Contains the DeviceIdentifier class for identifying devices
│   ├── utils.py            - Utility functions for network scanning
│   └── types
│       └── __init__.py     - Exports interfaces/types for device information
├── requirements.txt        - Lists project dependencies
└── README.md               - Documentation for the project
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd network-scanner
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

To run the network scanner, first activate the virtual environment:

On Windows (PowerShell):
```
.\.venv\Scripts\activate
```

Then run the scanner:
```
python src/scanner.py
```

Note: You may need to run PowerShell as Administrator for the network scanning to work properly.

This will initiate a scan of the local network and output the list of connected devices along with their types and brands.

## Dependencies

- `scapy`: For network scanning capabilities.
- `requests`: For making API calls to identify device brands.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.
