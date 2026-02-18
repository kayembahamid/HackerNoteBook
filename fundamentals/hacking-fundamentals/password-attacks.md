# Password Attacks

## Dictionary Attacks

### <mark style="color:blue;">Overview</mark>

Dictionary attacks are a common type of password attack that relies on a predefined list of words, phrases, or commonly used passwords, known as a "dictionary." In this attack, the attacker systematically tries each word from the dictionary as a possible password to gain unauthorized access to a system or account.

The attack is based on the assumption that many users choose weak passwords that are easy to guess. The dictionary can include common words, names, patterns, and commonly used combinations. The attacker uses automated tools that iterate through the dictionary, trying each word as a password until a successful match is found.

{% embed url="https://nordpass.com/most-common-passwords-list/" %}

### <mark style="color:blue;">Rockyou wordlist</mark>

Rockyou is a widely known and extensively used wordlist in the field of password cracking and security testing. It gained its popularity due to the large number of passwords it contains, derived from a breach of the Rockyou website in 2009. The wordlist consists of millions of commonly used passwords, dictionary words, and combinations that users often use to secure their accounts.

Security professionals and ethical hackers often leverage the Rockyou wordlist during password auditing and penetration testing to identify weak passwords and assess the strength of an organization's security. It serves as a valuable resource for testing the effectiveness of password policies and highlighting the importance of using strong, unique, and hard-to-guess passwords.

rockyou.txt contains 14,341,564 unique passwords, used in 32,603,388 accounts.

Kali Linux provides this dictionary file as part of its standard installation.

{% embed url="https://github.com/josuamarcelc/common-password-list/tree/main/rockyou.txt" %}

## Brute Force Attacks

Brute force attacks are a type of password cracking technique that involves systematically trying all possible combinations of characters until the correct password is discovered. The attacker uses automated software or scripts to repeatedly attempt different passwords until a match is found. Here are some key points about brute force attacks:

1. **Time-Consuming:** Brute force attacks can be time-consuming, especially for complex passwords with a large number of possible combinations. The time required depends on the password length, complexity, and the computing power available to the attacker.
2. **Password Length and Complexity:** Brute force attacks are more effective against weak passwords, such as short and simple ones. Longer and more complex passwords, including a combination of uppercase and lowercase letters, numbers, and special characters, significantly increase the time required to crack them.
3. **Resource Intensive:** Brute force attacks can be resource-intensive, requiring significant computational power and time to execute. As a result, attackers often leverage powerful machines or distributed computing networks to accelerate the cracking process.
4. **Countermeasures:** To protect against brute force attacks, organizations and individuals can implement several countermeasures. These include enforcing strong password policies, implementing account lockouts or delays after a certain number of failed login attempts, and using multi-factor authentication (MFA) to add an additional layer of security.
5. **Brute Force Detection and Prevention:** Intrusion detection systems (IDS) and intrusion prevention systems (IPS) can be deployed to monitor and identify patterns of brute force attacks. These systems can automatically block or limit access from suspicious IP addresses or implement rate-limiting measures to mitigate the impact of such attacks.
6. **Password Complexity and Length:** Users are encouraged to create strong and unique passwords, with a combination of uppercase and lowercase letters, numbers, and special characters. Longer passwords, ideally more than 12 characters, provide better resistance against brute force attacks.
7. **Regular Password Updates:** It is important to regularly update passwords to prevent them from being cracked through brute force attacks. Using a password manager to generate and store complex, unique passwords for each account can help with this process.

It is crucial to implement proper security measures and educate users about the risks of weak passwords and the importance of strong authentication practices to mitigate the threat of brute force attacks.

## Hashcat

### Overview <a href="#overview" id="overview"></a>

Hashcat is a powerful password cracking tool that is widely used by security professionals and researchers to recover lost or forgotten passwords. It supports various attack modes, including brute-force, dictionary, and hybrid attacks, and can handle a wide range of hash types and encryption algorithms.

With Hashcat, you can leverage the processing power of GPUs (Graphics Processing Units) to accelerate the password cracking process, making it significantly faster compared to traditional CPU-based methods. It supports both single-hash and multi-hash cracking, allowing you to crack multiple passwords simultaneously.

Hashcat offers extensive customization options and rule-based attacks, where you can apply specific rules and transformations to the provided wordlist to generate password variations and increase the chances of success. It also supports distributed cracking, enabling multiple systems to work together in parallel to crack passwords more efficiently.

{% embed url="https://hashcat.net/wiki/doku.php" %}



## Hydra

Hydra is a password cracking tool that can be used to crack passwords for a variety of protocols, including SSH, FTP, Telnet, and HTTP. Hydra works by using a dictionary attack, which means that it tries all possible combinations of words and characters in a dictionary to crack the password.

Hydra is a powerful tool, but it can be slow to crack passwords, especially if the password is long and complex. Hydra also requires a large amount of processing power and memory to run effectively.

Hydra is a popular tool among security researchers and penetration testers. It can be used to test the security of systems and networks by trying to crack passwords for various accounts. Hydra can also be used to recover lost passwords.

### <mark style="color:blue;">The most commonly used commands in Hydra</mark>

* Supports a wide range of protocols, including SSH, FTP, Telnet, and HTTP.
* Can use a variety of attack methods, including dictionary attack, brute-force attack, and hybrid attack.
* Supports parallel cracking, which can significantly speed up the cracking process.
* Can be used to crack passwords for local accounts, as well as remote accounts.

Here are some of the key features of Hydra:

Hydra is a popular tool among security researchers and penetration testers. It can be used to test the security of systems and networks by trying to crack passwords for various accounts. Hydra can also be used to recover lost passwords.

Hydra is a powerful tool, but it can be slow to crack passwords, especially if the password is long and complex. Hydra also requires a large amount of processing power and memory to run effectively.

Hydra is a password cracking tool that can be used to crack passwords for a variety of protocols, including SSH, FTP, Telnet, and HTTP. Hydra works by using a dictionary attack, which means that it tries all possible combinations of words and characters in a dictionary to crack the password.

### <mark style="color:blue;">How to use Hydra?</mark>

```
hydra -t 4 -l <username> -P <password_list> <target_ip> rdp
```

* RDP (Remote Desktop Protocol):

```
hydra -l <username> -P <password_list> <target_ip> mysql
```

* MySQL:

```
hydra -l <username> -P <password_list> <target_ip> telnet
```

* Telnet:

```
hydra -l <username> -P <password_list> <target_ip> ssh
```

* SSH:

```
hydra -l <username> -P <password_list> <target_ip> ftp
```

* FTP:

```
hydra -l <username> -P <password_list> <target_url> http-post-form "<login_url>:<login_parameters>:<failure_message>"
```

{% embed url="https://youtu.be/-CMBoJ60K1A" %}

### John the Ripper Password Cracker <a href="#hashcat-feautures" id="hashcat-feautures"></a>

#### Overview <a href="#overview" id="overview"></a>

John the Ripper is a popular open-source password cracker that is widely used for testing the strength of passwords and conducting password audits. It can be a valuable tool for security professionals and system administrators to assess the security of their systems and identify weak passwords.

{% embed url="https://www.openwall.com/john/" %}

{% embed url="https://www.youtube.com/watch?v=MHfylRCfccM" %}



<br>
