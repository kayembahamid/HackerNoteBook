# Cryptography Basic

**Common Hash Algorithms**

| Algorithm      | Output Size (bits)            | Speed                     | Security Status              | Common Use Cases                                                           |
| -------------- | ----------------------------- | ------------------------- | ---------------------------- | -------------------------------------------------------------------------- |
| **MD5**        | 128                           | Fast                      | Insecure (collision attacks) | File integrity checks (non-critical), legacy systems                       |
| **SHA-1**      | 160                           | Moderate                  | Insecure (collision attacks) | Legacy applications, digital signatures (deprecated)                       |
| **SHA-256**    | 256                           | Moderate                  | Secure                       | Digital signatures, certificates, blockchain                               |
| **SHA-3**      | Variable (224, 256, 384, 512) | Moderate                  | Secure                       | Cryptographic applications, post-quantum security                          |
| **SHA-512**    | 512                           | Slower                    | Secure                       | High-security applications, password hashing                               |
| **Blake2**     | Variable (up to 512)          | Very Fast                 | Secure                       | General-purpose hashing, cryptographic applications                        |
| **RIPEMD-160** | 160                           | Moderate                  | Secure (but less common)     | Cryptographic applications, digital signatures                             |
| **Whirlpool**  | 512                           | Slower                    | Secure                       | High-security applications, archival systems                               |
| **Argon2**     | Variable                      | Slower (memory-intensive) | Secure                       | Password hashing, key derivation                                           |
| **Tiger**      | 192                           | Fast                      | Secure (less common)         | Data integrity checks, cryptographic applications                          |
| **HMAC**       | Variable                      | Moderate                  | Secure                       | Message authentication in networking protocols (e.g., TLS, IPsec)          |
| **PBKDF2**     | Variable                      | Slower                    | Secure                       | Password hashing, key derivation                                           |
| **Skein**      | Variable (up to 1024)         | Moderate                  | Secure                       | Cryptographic applications, digital signatures                             |
| **Poly1305**   | 128                           | Very Fast                 | Secure                       | Message authentication in secure communication protocols (e.g., TLS, QUIC) |

* **Note**: Algorithms like MD5 and SHA-1 are no longer recommended for cryptographic purposes due to vulnerabilities to collision attacks. Modern applications should use SHA-2, SHA-3, or other secure algorithms like Blake2, Argon2, or HMAC for networking-related cryptographic needs.

**Symmetric Encryption**

Symmetric encryption uses a single key for both encryption and decryption. The same key must be securely shared between the communicating parties to ensure confidentiality.

* **Advantages**:
  * Faster and more efficient than asymmetric encryption due to simpler mathematical operations.
  * Requires less computational power, making it suitable for resource-constrained environments such as IoT devices.
  * Provides high throughput for encrypting large volumes of data.
* **Disadvantages**:
  * Key distribution can be challenging, as the same key must be securely shared between parties.
  * If the key is compromised, all encrypted data is at risk.
  * Does not provide non-repudiation, as the same key is used for both encryption and decryption.
* **Applications**:
  * **Data in Transit**:
    * Securing network traffic in VPNs, ensuring confidentiality and integrity.
    * Encrypting communication in protocols like HTTPS (in combination with asymmetric encryption for key exchange).
  * **Data at Rest**:
    * Encrypting sensitive files stored on disk to prevent unauthorized access.
    * Used in full-disk encryption tools like BitLocker and VeraCrypt.
  * **Messaging and Communication**:
    * Protecting messages in secure communication apps like Signal and WhatsApp.
    * Ensuring real-time encryption for voice and video calls.
  * **Database Encryption**:
    * Encrypting sensitive data stored in databases to comply with regulatory requirements.
    * Often used in conjunction with key management systems.
* **Key Management**:
  * Securely generating, storing, and distributing keys is critical for symmetric encryption.
  * Key management systems (KMS) are often used to automate and secure the lifecycle of encryption keys.
  * Techniques like key rotation and key expiration help mitigate risks associated with key compromise.
* **Best Practices**:
  * Always use modern, secure algorithms like AES or ChaCha20.
  * Avoid using deprecated algorithms like DES, 3DES, or RC4.
  * Implement strong key management policies to ensure the secure handling of encryption keys.
  * Use unique keys for different encryption contexts to minimize the impact of a key compromise.

Symmetric encryption remains a cornerstone of modern cryptography, offering a balance of speed and security for a wide range of applications. However, its reliance on secure key distribution highlights the importance of combining it with robust key management practices.

**Common Symmetric Encryption Algorithms**

| Algorithm    | Key Size (bits)    | Block Size (bits) | Security Status      | Common Use Cases                            |
| ------------ | ------------------ | ----------------- | -------------------- | ------------------------------------------- |
| **AES**      | 128, 192, 256      | 128               | Secure               | Data encryption, VPNs, file encryption      |
| **DES**      | 56                 | 64                | Insecure             | Legacy systems                              |
| **3DES**     | 112, 168           | 64                | Marginally Secure    | Legacy systems, compatibility requirements  |
| **Blowfish** | 32–448             | 64                | Secure               | Password hashing, file encryption           |
| **Twofish**  | 128, 192, 256      | 128               | Secure               | File encryption, disk encryption            |
| **RC4**      | 40–2048 (variable) | Stream cipher     | Insecure             | Legacy protocols (e.g., WEP, SSL)           |
| **ChaCha20** | 256                | Stream cipher     | Secure               | Secure communication protocols (e.g., TLS)  |
| **IDEA**     | 128                | 64                | Secure (less common) | Email encryption, PGP                       |
| **Camellia** | 128, 192, 256      | 128               | Secure               | Alternative to AES in cryptographic systems |

* **Deprecated Algorithms**:
  * **DES (Data Encryption Standard)**:
    * Uses a 56-bit key, which is now considered insecure due to brute-force vulnerabilities.
  * **3DES (Triple DES)**:
    * An improvement over DES but still vulnerable to certain attacks and slower compared to modern algorithms.
  * **RC4**:
    * A stream cipher that is no longer recommended due to known vulnerabilities.

**Asymmetric Encryption**

Asymmetric encryption uses a pair of keys: a public key for encryption and a private key for decryption. These keys are mathematically related but cannot be derived from one another. This approach eliminates the need for securely sharing a single key and enables secure communication between parties who have never met. Asymmetric encryption is a cornerstone of modern cryptography, enabling secure communication, authentication, and data integrity across a wide range of applications. Its combination with symmetric encryption in hybrid systems ensures both security and performance.

* **Advantages**:
  * Eliminates the need to securely share a single key.
  * Enables secure communication between parties who have never met.
  * Provides non-repudiation through digital signatures, ensuring that the sender cannot deny sending a message.
  * Allows for secure key exchange in combination with symmetric encryption.
* **Disadvantages**:
  * Slower than symmetric encryption due to more complex mathematical operations.
  * Requires more computational resources, which can be a limitation for resource-constrained devices.
  * Not suitable for encrypting large amounts of data due to performance constraints.
* **Usage in Applications**:
  * **Secure Key Exchange**:
    * Used in protocols like TLS to securely exchange session keys for symmetric encryption.
  * **Digital Signatures**:
    * Verifies the authenticity and integrity of documents, emails, or software.
    * Ensures that the message has not been tampered with and confirms the sender's identity.
  * **Email Encryption**:
    * Standards like PGP (Pretty Good Privacy) and S/MIME use asymmetric encryption to secure email communication.
  * **Authentication**:
    * Used in systems like SSH to authenticate users and devices.
  * **Blockchain Technology**:
    * Ensures the integrity and authenticity of transactions in blockchain networks.
  * **Certificate Authorities (CAs)**:
    * Asymmetric encryption is the foundation of Public Key Infrastructure (PKI), enabling secure HTTPS connections.
* **Key Management**:
  * Public keys can be freely shared, but private keys must be kept secure.
  * Digital certificates issued by trusted Certificate Authorities (CAs) are used to verify the authenticity of public keys.
  * Key rotation and revocation mechanisms are essential to maintain security.
* **Best Practices**:
  * Use modern algorithms like ECC or RSA with sufficiently large key sizes (e.g., 2048 bits or higher for RSA).
  * Avoid deprecated algorithms like 1024-bit RSA or older implementations of Diffie-Hellman.
  * Regularly update and rotate keys to minimize the risk of compromise.
  * Use trusted Certificate Authorities (CAs) to manage and verify public keys.

**Common Asymmetric Encryption Algorithms**

| Algorithm          | Key Size (bits)        | Security Status               | Common Use Cases                                 |
| ------------------ | ---------------------- | ----------------------------- | ------------------------------------------------ |
| **RSA**            | 1024, 2048, 3072, 4096 | Secure (2048+ recommended)    | Digital signatures, key exchange, certificates   |
| **ECC**            | 160–521                | Secure                        | Mobile devices, IoT, blockchain, TLS             |
| **DSA**            | 1024, 2048, 3072       | Secure (2048+ recommended)    | Digital signatures                               |
| **ElGamal**        | Variable               | Secure                        | Key exchange, encryption                         |
| **Diffie-Hellman** | Variable               | Secure (with large key sizes) | Key exchange                                     |
| **EdDSA**          | 256, 448               | Secure                        | Digital signatures, modern cryptographic systems |
| **Paillier**       | Variable               | Secure (less common)          | Homomorphic encryption                           |
| **NTRU**           | Variable               | Secure (post-quantum)         | Post-quantum cryptography                        |

* **Note**: RSA and ECC are the most widely used asymmetric algorithms. ECC is preferred for resource-constrained environments due to its smaller key sizes and faster computations. RSA remains popular for legacy systems and applications.

**Public Key Infrastructure (PKI)**

* **Definition**: PKI is a framework for managing digital certificates and public-key encryption to enable secure communication.
* **Components**:
  * **Certification Authority (CA)**: A trusted entity that issues and verifies digital certificates.
  * **Registration Authority (RA)**: Handles the verification of entities requesting certificates.
  * **Digital Certificates**: Bind public keys to entities, ensuring their authenticity.
  * **Certificate Revocation List (CRL)**: A list of certificates that have been revoked before their expiration date.
* **Applications**:
  * Enabling HTTPS for secure websites.
  * Managing digital signatures for documents and software.
  * Securing email communication using S/MIME.
  * Authenticating users and devices in enterprise environments.
* **Benefits**:
  * Provides a scalable and standardized approach to managing encryption keys.
  * Enhances trust in online transactions and communications.
  * Supports compliance with security standards and regulations.

#### Common Encryption Tools and Protocols

**SSL (Secure Sockets Layer) and TLS (Transport Layer Security)**

SSL (Secure Sockets Layer) and its successor TLS (Transport Layer Security) are cryptographic protocols designed to provide secure communication over a network. They are widely used to protect sensitive data and ensure privacy and integrity in online communications.

**How SSL/TLS Works**

1. **Handshake Process**:

* The handshake begins with the client and server exchanging information about supported cryptographic algorithms and protocols.
* The server provides its digital certificate, which contains its public key and is signed by a trusted Certificate Authority (CA).
* The client verifies the server's certificate to ensure its authenticity.
* A secure session key is established using asymmetric encryption (e.g., RSA or Diffie-Hellman).
* Once the session key is exchanged, symmetric encryption (e.g., AES or ChaCha20) is used for the actual data transfer to ensure efficiency.

2. **Session Establishment**:

* The session key is unique to each connection and is used to encrypt and decrypt data during the session.
* The use of symmetric encryption ensures high performance and low computational overhead.

3. **Data Integrity**:

* Message Authentication Codes (MACs) are used to verify the integrity of transmitted data.
* This ensures that any tampering or corruption during transmission is detected.

**Key Features of SSL/TLS**

* **Authentication**:
  * Ensures the identity of the server using digital certificates issued by trusted Certificate Authorities (CAs).
  * Optionally, client authentication can also be performed using client certificates.
* **Encryption**:
  * Protects data from being intercepted or read by unauthorized parties during transmission.
  * Supports a variety of encryption algorithms, including RSA, ECC, AES, and ChaCha20.
* **Integrity**:
  * Ensures that data is not altered during transmission using cryptographic hash functions like SHA-256.
* **Forward Secrecy**:
  * Modern implementations of TLS (e.g., TLS 1.2 and TLS 1.3) support forward secrecy, ensuring that even if the private key is compromised, past communications remain secure.

**Applications of SSL/TLS**

* **Web Traffic Security**:
  * Used in HTTPS to secure websites and protect user data such as login credentials, payment information, and personal details.
* **Email Encryption**:
  * Secures email communications using protocols like SMTPS, IMAPS, and POP3S.
* **VPN Connections**:
  * Protects data transmitted over Virtual Private Networks (VPNs) by encrypting the communication between the client and the VPN server.
* **File Transfers**:
  * Secures file transfers using protocols like FTPS and SFTP.
* **VoIP and Messaging**:
  * Encrypts voice and video calls, as well as instant messaging, to ensure privacy.
* **IoT Devices**:
  * Provides secure communication for Internet of Things (IoT) devices, protecting them from unauthorized access and data breaches.

**TLS Versions**

* **TLS 1.0**:
  * Introduced as a replacement for SSL 3.0 but is now deprecated due to security vulnerabilities.
* **TLS 1.1**:
  * Improved upon TLS 1.0 but is also deprecated.
* **TLS 1.2**:
  * Widely used and considered secure, supporting modern cryptographic algorithms and forward secrecy.
* **TLS 1.3**:
  * The latest version, offering improved performance, stronger security, and simplified handshake processes by removing outdated features.

**Common SSL/TLS Vulnerabilities**

* **Man-in-the-Middle (MITM) Attacks**:
  * Occur when an attacker intercepts and manipulates communication between the client and server.
  * Mitigated by using strong encryption and certificate validation.
* **Certificate Spoofing**:
  * Involves the use of fake certificates to impersonate a trusted server.
  * Prevented by verifying certificates against trusted Certificate Authorities.
* **Protocol Downgrade Attacks**:
  * Exploit older, less secure versions of SSL/TLS.
  * Mitigated by disabling deprecated protocols like SSL 3.0 and TLS 1.0.

**Best Practices for SSL/TLS**

* Use the latest version of TLS (preferably TLS 1.3) to ensure strong security.
* Configure servers to use strong cipher suites and disable weak ones.
* Regularly update and renew digital certificates to maintain trust.
* Implement HTTP Strict Transport Security (HSTS) to enforce HTTPS connections.
* Use Certificate Transparency logs to detect and prevent certificate misuse.

**GPG (GNU Privacy Guard)**

**GPG** is a free and open-source encryption software that implements the OpenPGP standard. It supports both **asymmetric encryption** (using a public-private key pair) and **symmetric encryption** (using a single shared key). GPG is commonly used for securing emails, files, and digital communications by encrypting data and digitally signing messages to ensure authenticity. Its flexibility and open-source nature make it highly customizable and accessible for personal and professional use.

**PGP (Pretty Good Privacy)**

**PGP** is an encryption program designed to secure data through encryption and digital signatures. It originally gained popularity for protecting email communications. PGP primarily uses **symmetric encryption**, which is simpler and faster for encrypting large amounts of data, but it also incorporates **asymmetric encryption** for key exchange and digital signatures. Now owned by Symantec, PGP is often used in commercial applications, although compatible tools like GPG provide a free alternative.

Both GPG and PGP aim to provide confidentiality, integrity, and authenticity for digital communications, and they can be used together due to their shared OpenPGP standard.

**OpenSSL:**

OpenSSL is a versatile tool that supports a wide range of cryptographic operations, making it essential for developers, system administrators, and security professionals.

Common uses:

<table data-header-hidden><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Use Case</strong></td><td><strong>Command</strong></td></tr><tr><td><strong>Generate private keys</strong></td><td><pre><code> openssl genrsa -out $private.key 2048 
</code></pre></td></tr><tr><td><strong>Extract public key from private key</strong></td><td><pre><code> openssl rsa -in $private.key -pubout -out $public.key
</code></pre></td></tr><tr><td><strong>Create a self-signed certificate</strong></td><td><pre><code> openssl req -x509 -new -nodes -key $private.key -sha256 -days 365 -out $certificate.crt
</code></pre></td></tr><tr><td><strong>Encrypt a file (Symmetric)</strong></td><td><pre><code> openssl enc -aes-256-cbc -in $file.txt -out $file.enc
</code></pre></td></tr><tr><td><strong>Decrypt a file (Symmetric)</strong></td><td><pre><code> openssl enc -aes-256-cbc -d -in $file.enc -out $file.txt
</code></pre></td></tr><tr><td><strong>Encrypt a file (Asymmetric)</strong></td><td><pre><code> openssl rsautl -encrypt -inkey $public.key -pubin -in $file.txt -out $file.enc
</code></pre></td></tr><tr><td><strong>Decrypt a file (Asymmetric)</strong></td><td><pre><code> openssl rsautl -decrypt -inkey $private.key -in $file.enc -out $file.txt
</code></pre></td></tr><tr><td><strong>Sign a file</strong></td><td><pre><code> openssl dgst -sha256 -sign $private.key -out $signature.bin $file.txt
</code></pre></td></tr><tr><td><strong>Verify a signature</strong></td><td><pre><code> openssl dgst -sha256 -verify $public.key -signature $signature.bin $file.txt
</code></pre></td></tr><tr><td><strong>Generate a CSR</strong></td><td><pre><code> openssl req -new -key $private.key -out $request.csr
</code></pre></td></tr><tr><td><strong>Convert to PEM format</strong></td><td><pre><code> openssl x509 -in $certificate.crt -outform PEM -out $certificate.pem
</code></pre></td></tr><tr><td><strong>Convert to DER format</strong></td><td><pre><code> openssl x509 -in $certificate.pem -outform DER -out $certificate.der
</code></pre></td></tr><tr><td><strong>Check certificate details</strong></td><td><pre><code> openssl x509 -in $certificate.crt -text -noout
</code></pre></td></tr><tr><td><strong>Test SSL/TLS connections</strong></td><td><pre><code> openssl s_client -connect $example.com:443
</code></pre></td></tr><tr><td><strong>Generate random string</strong></td><td><pre><code> openssl rand -base64 32
</code></pre></td></tr><tr><td><strong>Create a PKCS#12 file</strong></td><td><pre><code> openssl pkcs12 -export -out $certificate.pfx -inkey $private.key -in $certificate.crt -certfile $ca-bundle.crt
</code></pre></td></tr><tr><td><strong>Verify a certificate chain</strong></td><td><pre><code> openssl verify -CAfile $ca-bundle.crt $certificate.crt
</code></pre></td></tr><tr><td><strong>Benchmark AES-256-CBC</strong></td><td><pre><code> openssl speed aes-256-cbc
</code></pre></td></tr><tr><td><strong>Decode and inspect JWT tokens</strong></td><td><pre><code> echo "$eyJhbGciOi..." | base64 -d | openssl asn1parse -inform DER
</code></pre></td></tr></tbody></table>

**Other Encryption and encoding tools**

These tools are essential for encryption, hashing, and encoding tasks, providing a foundation for secure data handling and verification.

* **md5sum**:
  * A utility to compute and verify MD5 hash values.
  * Commonly used to check file integrity.
  * Example: `md5sum file.txt`
* **sha256sum**:
  * Similar to `md5sum`, but computes SHA-256 hash values for stronger security.
  * Example: `sha256sum file.txt`
* **Base64**:
  * Encodes and decodes data in Base64 format (not encryption!).
  * Useful for encoding binary data into text for safe transmission.
  * Example: `echo "Hello, World!" | base64`
* **GPG (GNU Privacy Guard)**:
  * A tool for secure communication and data encryption.
  * Supports signing, encrypting, and decrypting files and emails.
  * Example: `gpg --encrypt --recipient user@example.com file.txt`
* **bcrypt**:
  * A password hashing tool designed for secure password storage.
  * Example: `echo "password" | bcrypt`
* **pbkdf2**:
  * A key derivation function used to securely hash passwords.
  * Often implemented in libraries or tools for password management.
* **xxd**:
  * A utility to create a hexdump or reverse a hexdump back to binary.
  * Example: `xxd -p file.bin`

#### Encryption and its OSI Layer Relationships

* **Layer 4 (Transport)**: Establishes reliable connections (e.g., TCP handshake).
* **Layer 5 (Session)**: Manages secure sessions (e.g., TLS handshake).
* **Layer 6 (Presentation)**: Handles encryption, decryption, and data integrity (e.g., symmetric/asymmetric encryption, hashing).
* **Layer 7 (Application)**: Manages user-facing security mechanisms (e.g., PKI, digital certificates).

**Example: Steps of an HTTPS Connection**

1. **TCP Handshake** (OSI Layer 4 - Transport):

* The client and server establish a reliable connection using the TCP three-way handshake (SYN, SYN-ACK, ACK). This ensures that both parties are ready to communicate.

2. **Client → Server: ClientHello** (OSI Layer 5 - Session):

* The client initiates the TLS handshake by sending a `ClientHello` message. This includes supported TLS versions, cipher suites, and random data for key generation.

3. **Client ← Server: ServerHello + ServerKeyExchange** (OSI Layer 5 - Session):

* The server responds with a `ServerHello` message, selecting the TLS version and cipher suite. It also sends its digital certificate (containing its public key) to authenticate itself.

4. **Client → Server: ClientKeyExchange** (OSI Layer 5 - Session):

* The client generates a pre-master secret (shared secret) and encrypts it using the server's public key. This ensures that only the server can decrypt it using its private key.

5. **Key Generation and Symmetric Encryption** (OSI Layer 6 - Presentation):

* Both the client and server compute the session key (master key) from the pre-master secret. This session key is used for symmetric encryption, which is faster and more efficient for ongoing communication.

6. **Begin Symmetrically Encrypted Data Transfer** (OSI Layer 6 - Presentation):

* The server and client confirm the encryption parameters and switch to symmetric encryption for the remainder of the session. This ensures secure and efficient data transfer.

**Example: Email Encryption and Digital Signatures**

Email encryption and digital signatures are essential components of secure communication, ensuring that messages remain confidential, authentic, and tamper-proof. By encrypting a message, the sender ensures that only authorized parties can access the content, protecting it from unauthorized interception or eavesdropping.\
Below is an expanded explanation of how these mechanisms work and their role in maintaining security.

**Encrypting an Email**

To encrypt an email, a combination of **asymmetric encryption** and **symmetric encryption** is typically used for efficiency and security. This process ensures the confidentiality of the message while leveraging the strengths of both encryption types.

1. **Generate a Symmetric Key**:

* The sender generates a temporary symmetric key (also known as a session key) using a secure algorithm like AES (Advanced Encryption Standard). This key is used to encrypt the email content because symmetric encryption is faster and more efficient for large amounts of data.

2. **Encrypt the Email Content**:

* The email content is encrypted using the symmetric key. This ensures that the message is protected from unauthorized access.

3. **Encrypt the Symmetric Key**:

* The sender uses the **recipient's public key** (asymmetric encryption) to encrypt the symmetric key. This ensures that only the recipient, who has the corresponding private key, can decrypt the symmetric key.

4. **Send the Encrypted Email**:

* The encrypted email content and the encrypted symmetric key are sent to the recipient.

5. **Decryption by the Recipient**:

* The recipient uses their **private key** to decrypt the symmetric key.
* The decrypted symmetric key is then used to decrypt the email content, allowing the recipient to read the message.

**Why Use Both Asymmetric and Symmetric Encryption?**

* **Asymmetric Encryption**: Ensures secure key exchange. The recipient's public key is used to encrypt the symmetric key, guaranteeing that only the recipient can decrypt it with their private key.
* **Symmetric Encryption**: Provides efficient encryption for the email content, especially for large messages, as it is computationally faster than asymmetric encryption.

This hybrid approach combines the strengths of both encryption methods, ensuring secure and efficient email communication.

**Digital Signatures**

Digital signatures rely on **asymmetric encryption**, which uses a pair of keys.

A digital signature is created by the sender using their **private key**. This process involves generating a hash of the message and encrypting the hash with the sender's private key. The resulting digital signature is attached to the message.

When the recipient receives the message, they use the sender's **public key** to decrypt the digital signature and retrieve the hash. The recipient then generates a hash of the received message and compares it to the decrypted hash. If the two hashes match, it confirms that the message has not been tampered with and verifies the sender's identity.

Digital signatures enhance email security by addressing the following key aspects:

* **Authentication**: Verifies the sender's identity, ensuring that the email truly originates from the claimed source.
* **Integrity**: Confirms that the email content has not been altered during transmission.
* **Non-Repudiation**: Prevents the sender from denying that they sent the email, as the digital signature is uniquely tied to their private key.

**How Do Digital Signatures Work?**

1. **Creating a Digital Signature**:

* The sender generates a hash of the email content using a cryptographic hash function (e.g., SHA-256).
* The hash is then encrypted with the sender's private key, creating the digital signature.
* The digital signature is attached to the email along with the original message.

2. **Verifying a Digital Signature**:

* The recipient uses the sender's public key to decrypt the digital signature, retrieving the original hash.
* The recipient generates a new hash of the received email content.
* The two hashes are compared:
  * If they match, the email is verified as authentic and unaltered.
  * If they do not match, the email may have been tampered with or the sender's identity is not valid.

By combining digital signatures with encryption and hashing, email communication achieves a robust level of security, protecting sensitive information and ensuring trust between the sender and recipient.

Cryptography is for secure communications. It uses a wide variety of techniques.

### CyberChef Magic <a href="#cyberchef-magic" id="cyberchef-magic"></a>

[**CyberChef**](https://gchq.github.io/CyberChef/) is a swiss army knife for cryptography.\
Especially, **"Magic"** tool can process the given hashes automatically.\
So it's recommended to use the **"Magic"** at first. It can be found on the left pane.

### quipqiup <a href="#quipqiup" id="quipqiup"></a>

[quipqiup](https://www.quipqiup.com/) is an online cryptogram solver. It can solve substitution ciphers often found in newspapers, including puzzles like cryptoquips and patristocrats.

### OSINT <a href="#osint" id="osint"></a>

Before cracking, hashes might be revealed online so worth searching them with search engines.\
Below are Google Dorks for this purpose. Note that hashes are surrounded with double-quotes.

```
"WVLY0mgH0RtUI"
"5d41402abc4b2a76b9719d911017c592"
```

Also we can use **online tools** to decrypt.

### Identify the Cipher <a href="#identify-the-cipher" id="identify-the-cipher"></a>

#### Online Tools <a href="#online-tools" id="online-tools"></a>

* [Hashes](https://hashes.com/en/decrypt/hash)
* [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier)
* [Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
* [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/)

#### CLIs <a href="#clis" id="clis"></a>

*   Hashcat: Lists possible hash types.

    ```
    hashcat <hash>
    ```
* [HAITI](https://github.com/noraj/haiti)

#### Manual Identification <a href="#manual-identification" id="manual-identification"></a>

The following cryptos mean "hello".

```shellscript
# Base32
NBSWY3DPEB3W64TMMQ======
# Base58
StV1DL6CwTryKyV
# Base64
aGVsbG8gd29ybGQ=

# Binary
01101000 01100101 01101100 01101100 01101111 00100000 01110111 01101111 01110010 01101100 01100100

# Decimal
104 101 108 108 111 32 119 111 114 108 100

# Hex
68 65 6c 6c 6f 20 77 6f 72 6c 64
68656c6c6f20776f726c64

# Morse Code
.... . .-.. .-.. ---
.-- --- .-. .-.. -..

# MD4
aa010fbc1d14c795d86ef98c95479d17
# MD5
5eb63bbbe01eeed093cb22bb8f5acdc3

# ROT13
uryyb jbeyq
# ROT47
96==@ H@C=5

# SHA1
2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
# SHA256
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
# SHA512
9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
```

### Binary Data Manual Operations <a href="#binary-data-manual-operations" id="binary-data-manual-operations"></a>

Using **Python**.

#### 1. Change Hex to Base <a href="#id-1-change-hex-to-base" id="id-1-change-hex-to-base"></a>

```shellscript
import codecs

hex = "49276d206b6e6f"

b64 = codecs.encode(codecs.decode(hex, 'hex'), 'base64').decode()
print(b64)
```

#### 2. XOR <a href="#id-2-xor" id="id-2-xor"></a>

*   **Basic XOR**

    ```shellscript
    hex1 = "1c0111001f010100061a024b53535009181c"
    hex2 = "686974207468652062756c6c277320657965"

    xored_hex = hex(int(hex1, 16) ^ int(hex2, 16))
    # Display without prefix '0x' by slicing [2:]
    print(xored_hex[2:])
    ```
*   **Single-Byte XOR**

    ```shellscript
    # Basic function
    def single_byte_xor(text: bytes, key: int) -> bytes:
        return bytes([b ^ key for b in text])

    # ---------------------------------------------------------------

    # Enctyption
    ciphertext = single_byte_xor(b"hello", 69)
    print(ciphertext)

    # Decryption
    ciphertext = single_byte_xor(b"- ))*", 69)
    print(ciphertext)
    ```
*   **Crack Single-Byte XOR**

    ```shellscript
    import random
    import string
    from collections import Counter
    from typing import Tuple

    def single_byte_xor(text: bytes, key: int) -> str:
        return bytes([b ^ key for b in text])

    def fitting_quotient(text: bytes) -> float:
        counter = Counter(text)
        dist_text = [
            (counter.get(ord(ch), 0) * 100) / len(text)
            for ch in occurence_english
        ]

        return sum([abs(a - b) for a, b in zip(dist_english, dist_text)]) / len(dist_text)

    def decipher(text: bytes) -> Tuple[bytes, int]:
        original_text, encryption_key, min_fq = None, None, None
        for k in range(256):
            # Generate the plaintext using encryption key 'k'
            _text = single_byte_xor(text, k)
            # Compute the fitting quotient for this decrypted plaintext
            fq = fitting_quotient(_text)
            # If the fitting quotient of this generated plaintext is less than the minimum seen till now 'min_fq' we update.
            if min_fq is None or fq < min_fq:
                encryption_key, original_text, min_fq = k, _text, fq

        # Return the text and key that has the minimum fitting quotient
        return original_text, encryption_key


    plaintext = b"Hello world"
    plaintext = plaintext.lower()

    key = 82

    ciphertext = single_byte_xor(plaintext, key)

    occurence_english = {
        'a': 8.2389258, 'b': 1.5051398, 'c': 2.8065007, 'd': 4.2904556,
        'e': 12.813865, 'f': 2.2476217, 'g': 2.0327458, 'h': 6.1476691,
        'i': 6.1476691, 'j': 0.1543474, 'k': 0.7787989, 'l': 4.0604477,
        'm': 2.4271893, 'n': 6.8084376, 'o': 7.5731132, 'p': 1.9459884,
        'q': 0.0958366, 'r': 6.0397268, 's': 6.3827211, 't': 9.1357551,
        'u': 2.7822893, 'v': 0.9866131, 'w': 2.3807842, 'x': 0.1513210,
        'y': 1.9913847, 'z': 0.0746517
    }

    dist_english = list(occurence_english.values())

    sentences = [
        b'His mind was blown that there was nothing in space except space itself.',
        b'I love bacon, beer, birds, and baboons.',
        b'With a single flip of the coin, his life changed forever.',
        b'The three-year-old girl ran down the beach as the kite flew behind her.',
    ]

    for sentence in sentences:
        sentence = sentence.lower()
        encryption_key = random.randint(10, 220)
        assert decipher(single_byte_xor(sentence, encryption_key)) == (sentence, encryption_key,)

        (_plaintext, _key) = decipher(single_byte_xor(sentence, encryption_key))
        print(_plaintext)
        print(_key)
        print("\n")
    ```

### Crack Hashes <a href="#crack-hashes" id="crack-hashes"></a>

1. **Online Tools**
   * [**CrackStation**](https://crackstation.net/)
   * [**Hashes.com**](https://hashes.com/en/decrypt/hash)
2.  **Cracking Tools**

    First of all, you need to put the hash into the file like the following.

    ```
    echo -n '4bc9ae2b9236c2ad02d81491dcb51d5f' > hash.txt
    ```

    If you don't know which hash type it is, [**Example Hashes**](https://hashcat.net/wiki/doku.php?id=example_hashes) may help you.

    For brute forcing without wordlists in Hashcat, use the following command.

    ```
    hashcat -m <hash-mode> -a 3 '?a?a?a?a?a'
    ```

### Wordlists for Cracking <a href="#wordlists-for-cracking" id="wordlists-for-cracking"></a>

#### Fetch Wordlists <a href="#fetch-wordlists" id="fetch-wordlists"></a>

[Wordlistctl](https://github.com/BlackArch/wordlistctl) is a CLI that fetches, installs and searches wordlist archives from websites and torrent peers.

To fetch the wordlist, run as follow:

```shellscript
# -l: Wordlist
# -d: Decompress and remove archive
wordlistctl fetch -l dogs -d /usr/share/wordlists/misc/dogs.txt
wordlistctl fetch -l top_1000_usa_malenames_english -d /usr/share/wordlists/misc/top_1000_usa_malename_english.txt
wordlistctl fetch -l femalenames-usa-top1000 -d /usr/share/wordlists/usernames/femalenames-usa-top1000
```

#### Custom Wordlist <a href="#custom-wordlist" id="custom-wordlist"></a>

Below are some techniques to customize wordlists.

```shellscript
# Replace all 'c' with '$'
sed 's/c/$/g' origin.txt > new.txt

# Toggle the case of the second character
sed 's/\(.\)\(.\)\(.*\)/\1\U\2\E\3/g' origin.txt > new.txt
```

### Encrypt Files <a href="#encrypt-files" id="encrypt-files"></a>

```shellscript
openssl enc -in /etc/passwd -out /tmp/passwd
openssl enc -in /tmp/passwd -out /etc/passwd
```

### Useful Commands <a href="#useful-commands" id="useful-commands"></a>

*   **Generate Random Strings**

    ```shellscript
    # Hex encoded password
    openssl rand -hex 4
    ```
