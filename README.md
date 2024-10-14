# DNS-Sniffer

## Description
This Python script uses the `scapy` library to sniff DNS queries and responses. The tool captures UDP datagrams on port 53, both from the source and destination, allowing for real-time DNS traffic monitoring.

## Features
- Sniffs DNS queries and responses on the network.
- Displays packet details such as source and destination IPs.
- Color-coded output for better readability using `colorama`.
- User-friendly command-line interface with `argparse` for specifying the network interface.

## Tested on
- Kali LXDE Linux

## Installation
Before running the script, you need to install the required dependencies. Specifically, make sure to install Scapy by following the installation guide at:
[Scapy Installation Guide](https://scapy.readthedocs.io/en/latest/installation.html)

Additionally, install `colorama` for colorized output:
```bash
pip install colorama
```

## Usage
Ensure you run the script with super-user permissions since `scapy` requires administrative access for network sniffing.

```bash
sudo ./dnsSniffer.py -i <network_interface>
```
Replace `<network_interface>` with the actual interface name (e.g., `eth0`, `wlan0`).

### Example:
```bash
sudo ./dnsSniffer.py -i eth0
```

## Original Author
- By am0nt031r0

## Updated and Enhanced by
- Halil İbrahim, denizhalil.com

This updated version includes a refactor with improved structure, better error handling, colorized output, and argparse integration for enhanced functionality. 

## Check Out My Books
- **Mastering Linux Networking and Security: Essential and Advanced Techniques**  
  [Support on BuyMeACoffee](https://www.buymeacoffee.com/halildeniz/e/315997)
  
- **Mastering Scapy: A Comprehensive Guide to Network Analysis**  
  [Support on BuyMeACoffee](https://www.buymeacoffee.com/halildeniz/e/182908)
  
- **Mastering Python for Ethical Hacking: A Comprehensive Guide to Building Hacking Tools**

## Join the Community
Feel free to join our **Production Brain** Discord server to discuss cybersecurity, Python projects, and more:  
[Join Production Brain Discord](https://discord.gg/nGBpfMHX4u)

This project continues to grow with community feedback and contributions!
