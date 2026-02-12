# Firewall

It's a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules.

### Status <a href="#status" id="status"></a>

```shellscript
ufw status
ufw status verbose
```

### Enable/Disable the Firewall <a href="#enabledisable-the-firewall" id="enabledisable-the-firewall"></a>

```shellscript
ufw enable

ufw disable
```

### Set Default Policies <a href="#set-default-policies" id="set-default-policies"></a>

```shellscript
# Allow all
ufw default ALLOW

# Deny all
ufw default DENY
```

### Rules <a href="#rules" id="rules"></a>

*   **Allow**

    ```shellscript
    ufw allow 22
    ufw allow 22/tcp
    ufw allow 80
    ufw allow 80/tcp

    # Allow the given ip address access to port 22 for all protocols
    ufw allow from <ip> to any port 22
    ```
*   **Deny**

    ```shellscript
    ufw deny 22
    ufw deny 22/tcp
    ufw deny 80
    ufw deny 80/tcp
    ```
