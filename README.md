# 🚨 Snort NIDS Project

## 📘 Overview
This project demonstrates how to set up a Network Intrusion Detection System (NIDS) on Kali Linux using **Snort 3**. The system detects ICMP (ping) packets and raises alerts.

---

## 🧰 Configuration Files

- `snort.lua`: The Snort 3 configuration file
- `local.rules`: Contains a custom ICMP alert rule

---

## 🧪 Tested Environment

- **OS**: Kali Linux (running inside VMWare Workstation)
- **Snort Version**: 3.1.82.0
- **Interface**: `eth0`
- **Mode**: Passive detection

---

## 🚀 How to Run

```bash
sudo snort -c snort.lua -R local.rules -i eth0 --daq afpacket --daq-mode passive -A alert_fast


✅ Step-by-Step: Run Snort 3 NIDS on Linux
===============================================================================================================

🔹 Step 1: Verify Snort 3 Installation
Make sure Snort is installed and working:

snort -V
✅ You should see version info like: Snort++ 3.1.x.x (Paste the commands on Linux Terminal)

If not installed, install it:

sudo apt update
sudo apt install snort -y

----------------------------------------------------------------------------------------

🔹 Step 2: Create Configuration Files
Create config directory (if not already):

sudo mkdir -p /etc/snort/rules

Create the Snort configuration file:

sudo nano /etc/snort/snort.lua
Paste this:

HOME_NET = '192.168.146.97/24'  -- Replace with your VM's IP(See below to find ip)

ips = {
  enable_builtin_rules = true,
  include = '/etc/snort/rules/local.rules'
}

daq = {
  module = 'afpacket',
  interface = 'eth0',
  mode = 'passive'
}

decode = {}
search_engine = {}
stream = {}
reassembly = {}
file_id = {}

alert_fast = {
  file = true
}

Save and exit with CTRL + O, Enter, CTRL + X.

To find IP, Type "ip a" on your terminal
-----------------------------------------

Here’s a typical output of ip a:

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever

2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86375sec preferred_lft 86375sec
    inet6 fe80::aabb:ccff:fedd:eeff/64 scope link 
       valid_lft forever preferred_lft forever
Explanation of Key Parts:
lo: The loopback interface (used for local communication).

eth0: A physical or virtual Ethernet interface.

inet 192.168.1.100/24: The IPv4 address and subnet mask.

inet6 fe80::...: The IPv6 address.

state UP: Interface is active.

link/ether aa:bb:cc:dd:ee:ff: MAC address of the interface.

---------------------------------------------------------------------------------------------------------
Create your custom rule file:

sudo nano /etc/snort/rules/local.rules
Paste this rule:

alert icmp any any -> any any (msg:"🚨 My Custom ICMP Rule Triggered"; sid:1001337; rev:1;)
Save and exit.

-----------------------------------------------------------------------------------------------------------------

🔹 Step 3: Check Interface Name
Run:

ip a
Find the active interface name (e.g., eth0 or ens33).

------------------------------------------------------------------------------------------------------------------

🔹 Step 4: Run Snort with Config

sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i eth0 --daq afpacket --daq-mode passive -A alert_fast
✅ Replace eth0 with your actual interface name.

-------------------------------------------------------------------------------------------------------------------------------

🔹 Step 5: Test Snort Detection
From another device (or your host PC), ping the Kali VM:

ping <Kali_VM_IP>
Example:
bash
ping 192.168.146.97

Snort should output alerts like:

[**] [1:1001337:1] "🚨 My Custom ICMP Rule Triggered" [**] {ICMP} 192.168.146.171 -> 192.168.146.97
🟩 You're Done!

🧠 What You Can Learn from This Project
1. Intrusion Detection Concepts
Understand what Network Intrusion Detection Systems (NIDS) are and how they detect malicious or suspicious traffic.

Learn the difference between passive vs active detection.

2. Snort 3 Usage
How to install and configure Snort 3, one of the most widely used open-source IDS tools.

Learn Snort’s architecture: DAQ, rules, alerts, and output modules.

3. Writing Custom Detection Rules
Create Snort rules to detect specific types of traffic (e.g., ICMP ping).

Understand rule syntax: msg, sid, rev, proto, ip range, etc.

4. Network Traffic Monitoring
Use tcpdump and Snort to monitor real-time traffic on a network interface.

Practice identifying traffic sources, targets, and protocols.

5. Linux Administration
Work with Linux file system, permissions, services (systemctl, dpkg, etc.).

Learn how to debug common Linux and Snort errors using logs and error messages.

6. Packet Analysis
Capture and inspect network packets (e.g., ICMP, TCP).

See how tools like Snort interpret low-level data.

7. Virtual Networking
Understand networking within VMware Workstation (NAT, Bridged, Host-only).

Configure interfaces correctly for monitoring.

File Extension of .lua and .rules
------------------------------------

🔹 .lua Extension – snort.lua
What it is:
The .lua file is a configuration file written in the Lua programming language. In this context, it's specifically used for Snort 3, a popular Network Intrusion Detection System (NIDS).

Purpose in your project:
The snort.lua file is used to configure how Snort operates. It defines:

The network range (HOME_NET)

The interface and DAQ module Snort should listen on

Which rules to load (local.rules)

Basic modules like decode, stream, and file_id

Output format (e.g., alert_fast)

Example from your file:

lua

ips = {
  enable_builtin_rules = true,
  include = '/etc/snort/rules/local.rules'
}
This line tells Snort to use its built-in rules and also load custom rules from the local.rules file.

🔹 .rules Extension – local.rules
What it is:
The .rules file is a plain text file used to define custom detection rules for Snort. Each line typically represents a rule to detect certain types of traffic, such as suspicious packets or patterns.

Purpose in your project:
This file contains your custom detection logic. In your case, it defines a rule to alert when ICMP (ping) packets are detected.

Example from your file:

alert icmp any any -> any any (msg:"🚨 My Custom ICMP Rule Triggered"; sid:1001337; rev:1;)
This rule tells Snort to:

Alert on any ICMP packet from any source to any destination

Display the message "🚨 My Custom ICMP Rule Triggered"

Use a unique Snort ID (SID) of 1001337

==========================================================================================================================================