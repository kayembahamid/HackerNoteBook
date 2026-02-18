# Network Basics

## What is the internet ?

### <mark style="color:blue;">What is the internet?</mark>

The internet is a global network of interconnected computers and devices that communicate with each other using a common set of protocols. It is a vast collection of networks, servers, and infrastructure that enables the exchange of information and services across the globe.

The internet allows users to access a wide range of resources, including websites, email, social media, online services, and much more. It facilitates communication, collaboration, and the sharing of information on a global scale.

The internet has revolutionized the way we connect, communicate, and access information. It has transformed various aspects of our lives, including education, business, entertainment, and social interaction. Its open and decentralized nature has fostered innovation, creativity, and global connectivity.

### <mark style="color:blue;">Mac Address</mark>

A MAC address, short for Media Access Control address, is a unique identifier assigned to a network interface card (NIC) by the manufacturer. It consists of six pairs of hexadecimal numbers, separated by colons or hyphens. MAC addresses are used at the data link layer of the OSI model to uniquely identify devices within a local network. Unlike IP addresses, MAC addresses are assigned to the physical hardware and remain constant, making them useful for tasks such as network management, device tracking, and security.

### <mark style="color:blue;">IP Address</mark>

An IP address, short for Internet Protocol address, is a unique numerical label assigned to each device connected to a computer network that uses the Internet Protocol for communication. It serves two main functions: identifying the host or network interface and providing the location of the device in the network. IP addresses can be either IPv4 (32-bit) or IPv6 (128-bit) and play a crucial role in enabling communication and data exchange across the internet.

### <mark style="color:blue;">How to know you IP address and Mac Address</mark>

#### <mark style="color:blue;">on windows</mark>

you can simple write ipconfig on CMD

```
ipconfig 
```

#### <mark style="color:blue;">on Linux</mark>

to show Network interfaces

```
ifconfig
```

to show IP addresses

```
ip addr
```

#### <mark style="color:blue;">Using a Web Browser</mark>

{% embed url="https://nordvpn.com/what-is-my-ip/nord-vpn-site/" %}

{% embed url="https://www.myip.com/" %}

### <mark style="color:blue;">Networks Ports</mark>

Network ports are specific numbers used to identify different services or applications running on a device within a network. They facilitate the communication and exchange of data between devices by assigning unique port numbers to each service or application. Here are some common network ports and their associated services:

1. Port 80 (HTTP): Used for standard web browsing and accessing websites.
2. Port 443 (HTTPS): Used for secure web browsing with SSL/TLS encryption.
3. Port 22 (SSH): Used for secure remote access to servers.
4. Port 21 (FTP): Used for file transfer between computers.
5. Port 25 (SMTP): Used for sending email messages.
6. Port 110 (POP3): Used for receiving email messages.
7. Port 143 (IMAP): Used for accessing email messages on a server.
8. Port 53 (DNS): Used for domain name resolution.
9. Port 3389 (RDP): Used for remote desktop access.
10. Port 1194 (OpenVPN): Used for secure VPN connections.

These are just a few examples of commonly used network ports. There are many other ports assigned for various services and applications. Understanding network ports is important for configuring firewalls, routing traffic, and ensuring proper communication between devices in a network.

## Network devices

Network devices are physical devices that allow computers and other devices to connect to a network and communicate with each other. They come in a variety of shapes and sizes, and each has a different function.

Some of the most common network devices include:

* **Hubs**. Hubs are simple devices that connect multiple devices to the same network. They work by repeating all data packets that they receive to all connected devices.
* **Switches**. Switches are more intelligent than hubs and bridges. They can learn the MAC addresses of the devices connected to them and forward data packets only to the intended recipient. This allows for more efficient use of network bandwidth.&#x20;

{% embed url="https://www.youtube.com/watch?v=9eH16Fxeb9o" %}

* **Routers**. Routers are the most complex network devices. They connect different networks together, such as a home network to the internet. They do this by routing data packets between networks based on their destination IP addresses.

{% embed url="https://www.youtube.com/watch?v=p9ScLm9S3B4" %}

* Modem: A modem converts digital signals from a device into analog signals that can be transmitted over a telecommunications network. It allows devices to connect to the internet through an internet service provider (ISP).
* Wireless Access Point (WAP): A WAP allows wireless devices to connect to a wired network. It acts as a bridge between wireless and wired networks, enabling wireless communication.
* **Repeaters**. Repeaters are similar to hubs, but they amplify the signal as they repeat it. This allows them to extend the reach of a network.
* Network Interface Card (NIC): A NIC is a hardware component that enables a device to connect to a network. It provides the physical interface for devices to transmit and receive data over the network.
* Firewall: A firewall is a security device that monitors and controls network traffic based on predefined security rules. It helps protect the network from unauthorized access and potential threats.
* **Gateways**. Gateways connect two or more networks that use different protocols. For example, a gateway can connect a home network to a corporate network that uses a different type of network operating system.
* **Bridges**. Bridges connect two or more network segments that use the same type of network technology. They work by filtering out duplicate data packets and sending only the unique packets to each segment.

These are just some of the many different types of network devices. The specific devices that are used in a network will depend on the size and complexity of the network, as well as the specific needs of the organization.

## LAN / WAN

LAN (Local Area Network) and WAN (Wide Area Network) are two types of networks used in computer networking.

### <mark style="color:blue;">LAN</mark>

* A LAN is a network that covers a small geographical area, such as a home, office, or school.
* It connects devices within the same location, allowing them to share resources and communicate with each other.
* LANs are typically faster and have lower latency compared to WANs.
* Common LAN technologies include Ethernet and Wi-Fi.

### <mark style="color:blue;">WAN</mark>

* A WAN is a network that covers a large geographical area, often spanning multiple cities, countries, or even continents.
* It connects multiple LANs and allows for long-distance communication.
* WANs are typically slower and have higher latency compared to LANs due to the longer distance between devices.
* WANs are often established using leased lines, satellite links, or internet connections.

### <mark style="color:blue;">Differences between LAN and WAN</mark>

* Size and Coverage: LANs cover a smaller area, while WANs cover a larger area.
* Distance: LANs operate within a short distance, typically a few hundred meters, while WANs can span across vast distances.
* Speed and Latency: LANs offer higher speed and lower latency compared to WANs.
* Ownership and Control: LANs are privately owned and controlled by a single organization, while WANs may involve multiple organizations and service providers.

Both LANs and WANs play important roles in network connectivity, with LANs providing local connectivity and WANs enabling global connectivity.

### <mark style="color:blue;">Public IP VS Local IP</mark>

A public IP address and a local IP address are two distinct types of IP addresses used in networking.

1. Public IP Address: A public IP address is a unique identifier assigned to a device connected to a network, such as the internet. It is provided by your Internet Service Provider (ISP) and serves as the address used to communicate with devices outside of your local network. Your public IP address allows your device to connect to other devices and services on the internet.
2. Local IP Address: A local IP address, also known as a private IP address, is used within a local network to identify devices and facilitate communication. It is not directly accessible from the internet. Local IP addresses are typically assigned by a router or DHCP server and are used for internal network communication. They allow devices within the same network to communicate with each other and access shared resources.

The most common range of private IP addresses used in local networks are:

* IPv4: 192.168.0.0 to 192.168.255.255, 172.16.0.0 to 172.31.255.255, and 10.0.0.0 to 10.255.255.255.
* IPv6: fc00::/7.

Public IP addresses are necessary for devices to communicate over the internet, while local IP addresses are used for communication within a local network. It's important to understand the distinction between the two when configuring network devices and understanding network communication.

## VPN (Virtual Private Network)

### <mark style="color:blue;">What is a VPN</mark>

A VPN, or Virtual Private Network, is a technology that creates a secure and encrypted connection over a public network, typically the internet. It allows users to access a private network remotely as if they were directly connected to it, ensuring privacy, security, and anonymity.

When you connect to a VPN, your device establishes a secure tunnel to the VPN server, encrypting all data transmitted between your device and the server. This encryption protects your data from being intercepted and accessed by unauthorized parties.

VPNs are widely used by individuals, businesses, and organizations to secure their internet connections, protect sensitive data, and maintain online privacy.

### <mark style="color:blue;">VPN benefits</mark>

1. **Security:** VPNs encrypt your internet traffic, protecting it from hackers, surveillance, and other security threats.
2. **Privacy:** By masking your IP address and encrypting your data, VPNs enhance your privacy online, preventing your internet service provider (ISP), government, or other entities from tracking your online activities.
3. **Anonymity:** VPNs can help maintain anonymity by hiding your real IP address and location, making it harder for websites and online services to identify you.
4. **Access to restricted content:** VPNs can bypass geo-restrictions, allowing you to access regionally blocked content and websites.
5. **Remote access:** VPNs enable secure remote access to private networks, allowing users to work remotely and access resources as if they were on-site.

### <mark style="color:blue;">Most Used VPN</mark>

{% embed url="https://www.torproject.org/" %}

{% embed url="https://nordvpn.com/" %}

### <mark style="color:blue;">How a VPN works</mark>

* LCDP S3 E4 18:20 PROF
* LCDP S4 E1 -4.15 DEEP

{% embed url="https://youtu.be/sr2-K6AaHNI" %}

**A VPN, or Virtual Private Network**, works by creating a secure and encrypted connection between your device (such as a computer, smartphone, or tablet) and a remote server. Here's a simplified overview of how a VPN works:

1. **Encryption:** When you connect to a VPN, your data is encrypted before it leaves your device. This means that your internet traffic is encoded in a way that only the VPN server can decrypt it.
2. **Tunneling:** The encrypted data is then encapsulated within a secure tunnel. This tunnel protects your data from being intercepted or accessed by unauthorized parties while it travels over the internet.
3. **VPN Server:** The encrypted data is sent to a VPN server located in a different geographic location or region. This server acts as an intermediary between your device and the internet.
4. **IP Address Masking:** When your data reaches the VPN server, it is decrypted and sent out to the internet on your behalf. The VPN server assigns you a new IP address, masking your original IP address and providing you with anonymity and privacy.
5. **Secure Connection:** As your data travels between your device and the VPN server, it is protected from eavesdropping, hacking, or monitoring by malicious actors. This ensures that your online activities are private and secure.

By using a VPN, you can access the internet with an added layer of security and privacy. It allows you to browse the web anonymously, access geographically restricted content, and protect your sensitive information from prying eyes.

Different VPN services use different kinds of encryption processes, but put simply, the VPN encryption process goes something like this:

* When you connect to a VPN, it is through a secure tunnel where your data is encoded. This means that your data is transformed into an unreadable code as it travels between your computer and the server of the VPN.
* Your device is now seen as being on the same local network as your VPN. So your IP address will actually be the IP address of one of your VPN Provider’s servers.
* You may browse the internet as you please, safe in the knowledge that the VPN acts as a barrier, protecting your personal information.

### <mark style="color:blue;">VPN Types</mark>

There are several types of VPNs available, each designed to cater to specific needs and use cases. Here are some common types of VPNs:

1. **Remote Access VPN**: This type of VPN allows individual users to securely connect to a private network remotely over the internet. It is commonly used by employees working from home or while traveling to access company resources.
2. **Site-to-Site VPN:** Also known as a router-to-router VPN, this type of VPN connects multiple networks (such as branch offices) together over the internet. It enables secure communication and data transfer between different locations of an organization.
3. **Client-to-Site VPN:** In this setup, individual users connect to a VPN server using client software, establishing a secure connection to access resources within a private network. It provides remote access to specific applications or services.
4. **Layer 2 Tunneling Protocol (L2TP) VPN:** L2TP is a protocol used to establish VPN connections. It creates a tunnel between the client device and the VPN server and encapsulates data within the IPsec protocol for encryption and security.
5. **Secure Socket Tunneling Protocol (SSTP) VPN:** SSTP is another protocol used for VPN connections, primarily on Windows operating systems. It provides a secure connection by encapsulating traffic within the SSL/TLS protocol.
6. **OpenVPN:** OpenVPN is an open-source VPN protocol known for its flexibility and strong security features. It uses a custom security protocol based on SSL/TLS and supports various encryption algorithms.

These are just a few examples of VPN types available. The choice of VPN type depends on the specific requirements, network architecture, and level of security needed for the intended use.

### <mark style="color:blue;">VPN protocols</mark>

There are several VPN protocols available, each offering different levels of security and performance. Here are some commonly used VPN protocols:

1. **OpenVPN:** OpenVPN is an open-source protocol known for its strong security and flexibility. It uses SSL/TLS encryption to secure the connection and supports various encryption algorithms. OpenVPN is widely supported on different platforms and is considered one of the most reliable protocols.
2. **IPSec:** IPSec (Internet Protocol Security) is a suite of protocols used to secure internet communications. It provides authentication, integrity, and confidentiality through the use of encryption algorithms. IPSec can be used in either tunnel mode or transport mode and is commonly used in enterprise VPNs.
3. **L2TP/IPSec:** L2TP (Layer 2 Tunneling Protocol) is often combined with IPSec to enhance security. L2TP creates a tunnel for data transmission, while IPSec handles encryption and authentication. L2TP/IPSec is widely supported but may have lower performance due to double encapsulation.
4. **PPTP: PPTP** (Point-to-Point Tunneling Protocol) is an older and less secure protocol. It is known for its simplicity and compatibility but has known security vulnerabilities. PPTP is not recommended for sensitive data or high-security applications.
5. **WireGuard:** WireGuard is a relatively new and lightweight VPN protocol that aims to provide high-speed performance and strong security. It utilizes modern encryption algorithms and has gained popularity for its simplicity and efficiency.

When choosing a VPN protocol, consider the level of security, compatibility with your devices, and the intended use (e.g., streaming, gaming, or privacy). It's important to select a protocol that balances security and performance based on your specific needs.

## Deep and Dark Web

### <mark style="color:blue;">What Is the Deep Web?</mark>

The deep web is a part of the internet that is not indexed by search engines. This means that it is not accessible through regular search queries. The deep web is estimated to be 96% of the entire internet.

There are many reasons why websites are hidden on the deep web. Some websites are password-protected, such as banking websites and social media profiles. Others are behind paywalls, such as academic journals and research papers. Still others are hidden for legal reasons, such as whistleblowing websites and political activism platforms.

The deep web can also be used for illegal activities, such as drug trafficking, weapons trading, and human trafficking. However, it is important to note that not all activity on the deep web is illegal. There are also legitimate uses for the deep web, such as whistleblowing and political activism.

If you are considering accessing the deep web, it is important to take precautions to protect your privacy and security. Some tips include:

* Use a strong VPN to encrypt your traffic.
* Be careful about what information you share.
* Avoid clicking on links or opening attachments from unknown sources.
* Be aware of the risks and use common sense.

The deep web can be a dangerous place, but it can also be a valuable resource. By taking the necessary precautions, you can stay safe and use the deep web for legitimate purposes.

### <mark style="color:blue;">What Is the Dark Web?</mark>

The dark web is a part of the internet that is not indexed by search engines. This means that it cannot be accessed using a regular web browser, such as Chrome or Firefox. To access the dark web, you need to use a special browser, such as Tor.

The dark web is often used for illegal activities, such as drug trafficking, weapons trading, and human trafficking. However, there are also legitimate uses for the dark web, such as whistleblowing and political activism.

Here are some of the things that you can find on the dark web:

* Black markets: These are websites where people can buy and sell illegal goods and services, such as drugs, weapons, and stolen credit cards.
* Forums: These are online discussion boards where people can talk about anything, including illegal activities.
* Chat rooms: These are online chat rooms where people can communicate with each other anonymously.
* File sharing: These are websites where people can share files, such as movies, music, and software.
* Tor hidden services: These are websites that are hosted on the Tor network and are only accessible using the Tor browser.

The dark web can be a dangerous place, but it can also be a valuable resource. By taking the necessary precautions, you can stay safe and use the dark web for legitimate purposes.

### <mark style="color:blue;">How to Access the Deep/Dark Web Safely</mark>

{% embed url="https://www.youtube.com/watch?v=4ljq8JMFbJM" %}

#### <mark style="color:blue;">Using Tor Browser</mark>

The Tor Browser is a privacy-focused web browser that allows users to access the internet while maintaining a higher level of anonymity and security. It's primarily designed to access websites hosted on the Tor network, which is a decentralized network of volunteer-operated servers that route internet traffic to conceal a user's identity and location. Here are some key points about the Tor Browser:

* **Anonymity:** The Tor Browser routes your internet traffic through a series of relays, making it difficult for anyone, including ISPs and websites, to trace your online activities back to your IP address.
* **Privacy:** By blocking third-party trackers and cookies, the Tor Browser enhances your privacy by preventing advertisers and websites from collecting information about your browsing habits.
* **Accessing the Tor Network:** The Tor Browser is the recommended and most common way to access websites hosted on the Tor network. These websites have URLs ending in ".onion."
* **Security:** The Tor Browser is designed with security in mind. It isolates each website in a separate container, reducing the risk of tracking and cross-site attacks.
* **Built-in Encryption:** The traffic within the Tor network is encrypted, adding an extra layer of security to your communications.
* **Downloading and Updates:** It's important to download the Tor Browser from the official Tor Project website to ensure you're using the legitimate and secure version. Keep the browser updated to benefit from security patches and improvements.
* **Slow Speed:** Due to the nature of routing traffic through multiple relays, browsing with the Tor Browser can be slower than using a regular browser.
* **User-Friendly Interface:** The Tor Browser's interface is similar to other web browsers, making it easy for users to navigate and access websites.
* **Anonymity Trade-offs:** While the Tor Browser provides a high level of anonymity, it's important to note that no tool can guarantee absolute anonymity. Careful browsing habits and understanding the limitations of Tor are crucial.
* **Ethical Considerations:** The Tor network is used by people around the world for various reasons, including evading censorship, protecting privacy, and accessing information in repressive environments. It's important to respect the ethical guidelines of using Tor.

Using the Tor Browser can be a valuable tool for maintaining online privacy and accessing information while avoiding censorship, but it's important to be aware of its limitations and potential risks. Always use the Tor Browser responsibly and stay informed about the latest developments in privacy and security practices.

{% embed url="https://www.youtube.com/@TCMSecurityAcademy" %}

#### <mark style="color:blue;">Using Tails OS</mark>

"Tails" (The Amnesic Incognito Live System) is a privacy-focused operating system designed to provide secure and anonymous access to the internet. It's often used for sensitive tasks like online research, secure communications, and maintaining privacy while browsing. Here's how you can use Tails OS:

* **Download Tails:** Visit the official Tails website and download the Tails ISO image. Verify the download's integrity using the provided instructions.
* **Create a Tails USB Drive:** Follow the Tails installation guide to create a bootable USB drive using the downloaded ISO image. This USB drive will be used to boot into the Tails operating system.
* **Boot into Tails:** Insert the Tails USB drive into your computer and restart it. Access the boot menu and select the USB drive as the boot device. Tails will boot directly from the USB drive without affecting your computer's primary operating system.
* **Use Tails:** Once Tails has booted, you'll have access to a secure and private operating system. Tails routes your internet traffic through the Tor network by default, providing anonymity while browsing.
* **Browsing and Communication:** You can use the built-in Tor Browser for anonymous web browsing. Tails also includes various secure communication tools like encrypted email clients and instant messaging apps.
* **Secure Persistence:** Tails offers the option of creating an encrypted "persistent volume" on a separate USB drive or an encrypted storage partition. This allows you to save data, bookmarks, and settings securely between Tails sessions.
* **Leaving No Trace:** Tails is designed to leave no traces on the computer you're using. All data is stored in RAM and wiped upon shutdown, ensuring that no information is left behind.
* **Understanding Limitations:** While Tails provides strong privacy and anonymity, it's important to remember that no tool can provide absolute security. Proper usage, cautious online behavior, and understanding the risks are essential.
* **Keep Tails Updated:** Regularly update your Tails installation to benefit from security patches and improvements.
* **Shutdown and Eject:** After using Tails, shut down the system and remove the USB drive. This ensures that no traces of your activities remain on the computer.

Tails can be an effective tool for maintaining privacy and anonymity online, especially in situations where you need to protect your identity and data. However, it's important to familiarize yourself with its features, limitations, and security practices to use it effectively and responsibly.

{% embed url="https://www.youtube.com/watch?v=gO9fTnMxwYw" %}

## Networking Commands

### <mark style="color:blue;">Common Networking Commands</mark>

There are many common networking commands that are used to troubleshoot and manage networks. Here are some of the most common ones:

#### <mark style="color:blue;">**Ping**</mark>

**Ping:** The ping command is used to test the connectivity between two hosts. It sends ICMP echo request messages to the destination host and waits for ICMP echo reply messages. If the ping command gets a reply from the destination host, it means that the hosts are connected and that the network is working.

```
ping www.google.com
```

#### <mark style="color:blue;">**Ipconfig**</mark>

**Ipconfig:** The ipconfig command is used to display the IP address configuration of the local machine. It also displays other information, such as the subnet mask, default gateway, and DNS server addresses.

```
Ipconfig
```

#### <mark style="color:blue;">iwconfig</mark>

iwconfig: Displays wireless network interface configuration and settings.

```
iwconfig
```

#### <mark style="color:blue;">ifconfig</mark>

ifconfig: Displays the network interface configuration, including IP addresses and network details.

```
ifconfig
```

#### <mark style="color:blue;">netstat</mark>

The netstat command is a networking command that is used to display network connections, routing tables, and interface statistics. It can be used to troubleshoot network problems and to monitor network traffic.

```
netstat [options]
```

The `options` can be any of the following:

* `-a` - Display all connections, including listening ports.
* `-n` - Display addresses and port numbers in numerical form.
* `-o` - Display the owning process ID associated with each connection.
* `-p` - Display connections for the protocol specified by `proto`. For example, `netstat -p tcp` will display all TCP connections.
* `-r` - Display the routing table.
* `-t` - Display connections for the transport protocol specified by `proto`. For example, `netstat -t tcp` will display all TCP connections.
* `-u` - Display connections for the user specified by `user`.

#### <mark style="color:blue;">**Tracert**</mark>

**Tracert:** The tracert command is used to trace the path that a packet takes from the source host to the destination host. It does this by sending ICMP echo request messages to the destination host and recording the IP addresses of the routers that the packets pass through.

```
Tracert www.google.com
```

#### <mark style="color:blue;">**Netstat**</mark>

**Netstat:** The netstat command is used to display the network connections and listening ports on the local machine. It can also be used to display the routing table.

```
netstat -option
```

options:

* `-a` - Display all connections, including listening ports. Other options that can be used with the netstat command include:
* `-n` - Display addresses and port numbers in numerical form.
* `-o` - Display the owning process ID associated with each connection.
* `-p` - Display connections for the protocol specified by `proto`. For example, `netstat -p tcp` will display all TCP connections.
* `-r` - Display the routing table.

#### <mark style="color:blue;">**Nslookup**</mark>

**Nslookup:** The nslookup command is used to query the Domain Name System (DNS) for information about a hostname or IP address.

```
nslookup www.google.com
```

#### <mark style="color:blue;">**Route**</mark>

**Route:** The route command is used to manage the routing table on the local machine. It can be used to add, delete, and modify routes.

```
route [options] [destination] [gateway] [metric]
```

The `options` can be any of the following:

* `add` - Add a route to the routing table.
* `delete` - Delete a route from the routing table.
* `change` - Change the metric of a route in the routing table.
* `print` - Print the routing table.

The `destination` is the network or host that the route is for. The `gateway` is the IP address of the router that is used to reach the destination. The `metric` is an integer that specifies the cost of the route.

#### <mark style="color:blue;">**Telnet**</mark>

The telnet command is used to establish a remote terminal connection to another host. This can be used to troubleshoot problems on remote hosts or to administer network devices. The syntax for the telnet command is:

```
telnet [options] [host] [port]
```

The `options` can be any of the following:

* `-a` - Specifies the local username.
* `-l` - Specifies the remote username.
* `-r` - Specifies the remote hostname.
* `-v` - Specifies the verbose mode.

#### <mark style="color:blue;">TCPDUMP</mark>

This tcpdump release fixes an out-of-bounds write vulnerability (CVE-2023-1801) present in the previous release (4.99.3) in the SMB printer, which is not compiled by default. It also makes various minor improvements. This release requires libpcap 1.10.0 or later to pass all test cases.

```
tcpdump [Options]
```

### <mark style="color:blue;">NMAP</mark>

#### <mark style="color:blue;">Overview</mark>

Nmap (Network Mapper) is a powerful network scanning tool used to discover hosts and services on a computer network. It provides a wide range of scanning techniques and options to gather information about network devices, open ports, operating systems, and other details. Nmap uses raw IP packets to determine available hosts and services, making it flexible and efficient for network reconnaissance. It supports various scan types, including TCP, UDP, SYN, and ICMP, and can perform advanced tasks like version detection, OS fingerprinting, and script scanning. Nmap is widely used by network administrators, security professionals, and ethical hackers for network analysis and vulnerability assessment.

#### <mark style="color:blue;">NMAP Options</mark>

* **Target specification:** This option specifies the hosts or networks to be scanned. You can specify hostnames, IP addresses, or network ranges.
* **Host discovery:** This option controls how Nmap discovers hosts on the network. By default, Nmap will send ICMP echo requests to each target. You can also use TCP SYN or UDP probes to discover hosts.
* **Scan techniques:** This option specifies the type of scan to be performed. Nmap supports a variety of scan techniques, including SYN, TCP connect(), ACK, FIN, and Xmas scans.
* **Port specification:** This option specifies the ports to be scanned. You can specify individual ports, ranges of ports, or all ports.
* **Output format:** This option specifies the format of the scan output. Nmap can output its results in a variety of formats, including text, XML, and grepable.
* **Timing and performance:** These options control the speed and intensity of the scan. You can use these options to optimize the scan for your specific needs.
* **Miscellaneous options:** These options provide additional control over the scan. For example, you can use these options to disable DNS resolution, spoof your IP address, or run Nmap in stealth mode.

#### <mark style="color:blue;">NMAP Commands Options</mark>

* Basic Scan: `nmap <target>` - Performs a basic scan on the specified target IP address or hostname.
* Port Scan: `nmap -p <ports> <target>` - Scans specific ports on the target, e.g., `nmap -p 80,443 <target>`.
* Service and Version Detection: `nmap -sV <target>` - Detects the services running on open ports and attempts to determine their versions.
* OS Detection: `nmap -O <target>` - Attempts to identify the operating system of the target machine.
* Aggressive Scan: `nmap -A <target>` - Enables aggressive scanning techniques, including OS detection, version detection, script scanning, and traceroute.
* Script Scanning: `nmap --script <script> <target>` - Executes specific NSE scripts to perform additional scanning and information gathering.
* UDP Scan: `nmap -sU <target>` - Performs a UDP scan to identify open UDP ports on the target.
* Timing and Performance Options: `nmap -T<level> <target>` - Specifies the timing template for the scan, where the level can be from 0 to 5 (higher is faster, but less reliable).
* Output Options: `nmap -oX <filename> <target>` - Saves the scan results in XML format to the specified file.

{% embed url="https://www.youtube.com/@NetworkChuck" %}

