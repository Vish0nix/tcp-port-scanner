# TCP Port Scanner

A desktop TCP port scanner built with Python and Tkinter. Enter a host and an inclusive port range to check which TCP ports accept connections.

## Features

- Target hostname or IPv4 address
- Configurable port range from 1 to 65535
- Responsive interface with scan progress
- Stop an active scan
- Results list shows open ports
- No third-party packages required

## Requirements

Python 3 with Tkinter available. Tkinter is included with most desktop Python installations.

## Run

```powershell
python port_scanner.py
```

The default target is `127.0.0.1` and the default range is ports 1 through 1024.

## Use responsibly

Only scan systems you own or have explicit permission to test.
