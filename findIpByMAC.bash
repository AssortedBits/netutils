#!/bin/bash

# Usage: ./find_ip_by_mac.sh <MAC_ADDRESS> [SUBNET]
# Example: ./find_ip_by_mac.sh AB:CD:EF:12:34:56 192.168.1.0/24

MAC_INPUT=$(echo "$1" | tr '[:lower:]' '[:upper:]')
SUBNET="$2"

if [ -z "$MAC_INPUT" ]; then
    echo "Usage: $0 <MAC_ADDRESS> [SUBNET]"
    exit 1
fi

if grep -qi microsoft /proc/version; then
	echo "WSL is not supported, due to limitations in its default networking." >&2
	exit 4
fi


# If subnet is not given, try to auto-detect it
if [ -z "$SUBNET" ]; then
    echo "no subnet supplied. Deducing..."
    IFACE=$(ip route | awk '/default/ {print $5; exit}')
    if [ -z "$IFACE" ]; then
        echo "Could not determine network interface." >&2
        exit 2
    fi
    SUBNET=$(ip -o -f inet addr show "$IFACE" | awk '{print $4}')
    if [ -z "$SUBNET" ]; then
        echo "Could not determine subnet for interface $IFACE." >&2
        exit 3
    fi
fi

echo "Scanning subnet $SUBNET for MAC address $MAC_INPUT..."
echo

# Create a temp file for nmap output
TMPFILE=$(mktemp)

# Run nmap with progress, save output to temp file, and show progress to user
sudo nmap -sn --stats-every 2s "$SUBNET" 2>&1 | tee "$TMPFILE" | grep -E "^(Stats|ARP Ping Scan Timing):"

echo
echo "Scan complete. Searching for MAC address $MAC_INPUT..."

# Extract IP(s) matching the MAC address
awk -v mac="$MAC_INPUT" '
    BEGIN { IGNORECASE=1 }
    /^Nmap scan report for / { ip=$5 }
    /^MAC Address: / {
        if (index($3, mac) > 0) {
            print ip
        }
    }
' "$TMPFILE"

# Clean up
rm -f "$TMPFILE"
