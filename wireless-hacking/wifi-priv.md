# Wifi Priv

## WiFi Password Recovery <a href="#wifi-password-recovery" id="wifi-password-recovery"></a>

If we forget WiFi password, we may be able to recover password from the history.

### Windows <a href="#windows" id="windows"></a>

Open Command Prompt as Administrator and then execute the following commands:

```shellscript
# Show all network names you've accessed and saved
netsh wlan show profile

# Show the details of the specific network including password
netsh wlan show profile name="network-name" key=clear
```

### Linux <a href="#linux" id="linux"></a>

```shellscript
ls -al /etc/NetworkManager/system-connections/
cat /etc/NetworkManager/system-connections/example.nmconnection
```
