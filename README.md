# Who Built the Machines That Live in Our Homes?

This repo contains the Python code and notes from the blog post:  
👉 [Read the full post](https://adamkearsey.com/2025-05-12-Scan_Home_Network/)

---

##  What It Does

This script quietly inventories every device on your home network by:
- Sending ARP requests to discover active hosts
- Looking up MAC address vendors (manufacturer identification)
- Probing a list of common TCP ports (22, 80, 443, etc.)
- Logging results to a CSV file

Use it to:
- See what’s connected to your network
- Identify unknown devices
- Understand who built them — and what they might be doing

---

## Requirements

- `Python 3.x`
- `scapy`
- `mac-vendor-lookup`

## Install dependencies:

```bash
pip3 install scapy mac-vendor-lookup
```
## Usage

Update the subnet in scan.py to match your local network, e.g.:

subnet = '192.168.1.0/24'

Then run:
```bash
sudo python3 LocalNetworkScan.py
```
Output will be saved to:

`network_inventory.csv`

## Sample Output

![Image](https://github.com/user-attachments/assets/7bce8e29-3845-4549-81ce-163306a14797)


## License

    Code: MIT License – use freely with attribution

    Writing and blog content: CC BY 4.0

## Author

[Adam Kearsey](https://adamkearsey.com)

## Explore Further

    [CanYouSeeMe.org](https://canyouseeme.org) – Check external port exposure

    [macvendors.com](https://macvendors.com) – Look up MAC address vendors
