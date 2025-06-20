# VPN Manager for Exceleron OpenVPN Configurations

Advanced VPN connection manager with fuzzy matching, session management, and hooks support.

## Features

- Fuzzy matching for profile names ("pln essdlc" → pln/essdlc.ovpn)
- Profile aliases support
- Screen/tmux session management  
- Pre/post connect/disconnect hooks
- Status checking for active connections
- YAML configuration

## Usage

```bash
# Connect to VPN
~/ovpn/vpn-manager.sh connect "dal mup"

# Show status
~/ovpn/vpn-manager.sh status

# List profiles
~/ovpn/vpn-manager.sh list

# Disconnect
~/ovpn/vpn-manager.sh disconnect "dal mup"
```

## Configuration

Configuration is stored in `/home/chase/ovpn/vpn-config.yaml`