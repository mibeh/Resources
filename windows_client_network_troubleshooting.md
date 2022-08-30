# Windows Networking Troubleshooting Guide

### Questions to answer:
* Is an IP address assigned?
* What is the subnet mask?
* What is the default gateway?
* What is the DNS server set as?
* Which interface are you using to communicate?
* What port are you trying to reach?
* What protocol are you trying to talk over?
* Is the interface enabled?
* Is the firewall blocking your traffic?
* Do you need to be connected to a VPN?

### Windows Networking Commands:
**arp** - Displays and modifies the IP-to-Physical address translation tables used by address resolution protocol (ARP).

**ipconfig** - IP interface configuration details

**getmac** - Display the MAC address for network adapters on a system.

**netstat** - Displays protocol statistics and current TCP/IP network connections.

**nslookup** - Queries the specified DNS server and retrieves the records for the domain.

**ping** - Whatever you want it to be.

**route** - Manipulates network routing tables.

**tracert** - Trace the path that a packet. 


**After each step, check if you're networking issue is fixed.** 

## Step 1:
* Check Layer 1 (cables are pugged in and devices are powered on)

## Step 2:
* Check if the firewall is enabled and which profile is active (Domain, Public, Private)
    - netsh advfirewall show currentprofile
* Check your firewall rules
    - Open Windows Firewall with Advanced security, make note of the default behavior for traffic that does not match a rule. Check both inbound and outbound rules for anything that may be blocking your traffic. Filter by profile <Active Profile> and filter by state <Enabled>.

## Step 3:
* Check the interface config
    - ipconfig /all - find the relevant interface
    - To get to the adapter settings:
        - Right-click the network icon in the system tray
        - Right-click the relevant adapter > Properties
        - Scroll down to IPv4 > Properties (Disable IPv6 while you're here)
        - OR Control Panel > Network & Internet > Network & Sharing Center > Click connection name > Properties
    - If a DHCP address is not desired or isn't being assigned, unselect "Obtain an IP address Automatically"
    - Set a static IP address in the proper subnet, set the correct subnet mask, set the default gateway IP (confirm with Network Admin)
    - Set primary and seconday DNS servers (confirm with Network Admin)
    - It's usually best to check "Validate Settings Upon Exit"

## Step 4:
* Check what your default routes are
    - netstat -r
    - route print
    - If necessary, flush the routing table after statically setting your IP settings then  try to send the traffic you want (route -f)
* Check DNS records
    - ipconfig /displaydns

## Step 5:
* Make sure that the networking related services are running

## Step 6:
* Confirm MAC addresses in your ARP table are correct (may require interacting with other humans)

## Step 7:
* Start a packet captue to see if you can gain any more insight into the issue.
    - Wireshark
    - Windows Message Analyzer
        - (In Administrative Command Prompt)
        - netsh trace start capture=yes
        - netsh trace stop
        - Attach both files to the case
        - You can then save and export the capture to view in Wireshark
### If all of the above fails, **_THEN_** it's ok to yell at the network admin :)
