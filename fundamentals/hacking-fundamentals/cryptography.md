# Cryptography

## What is Cryptography ?

### <mark style="color:blue;">What is The Cryptography ?</mark>

Cryptography is the practice and study of techniques for secure communication in the presence of third parties. More generally, it is about constructing and analyzing protocols that prevent third parties or the public from reading private data, such as the content of electronic messages, or of passing forged messages as if they were from a trusted source.

### <mark style="color:blue;">**Terminologies of Cryptography**</mark>

Here are some of the most common terminologies used in cryptography:

* **Plaintext:** The original message that is being encrypted.
* **Ciphertext:** The encrypted message.
* **Encryption:** The process of converting plaintext into ciphertext.
* **Decryption:** The process of converting ciphertext back into plaintext.
* **Key:** A secret piece of information that is used to encrypt and decrypt messages.
* **Algorithm:** A mathematical process that is used to encrypt and decrypt messages.
* **Symmetric cryptography:** A type of cryptography that uses the same key to encrypt and decrypt messages.
* **Asymmetric cryptography:** A type of cryptography that uses two different keys to encrypt and decrypt messages: a public key and a private key.
* **Digital signature:** A type of cryptographic signature that is used to verify the authenticity of a digital message or document.
* **Hash function:** A mathematical function that converts data of any size into a fixed-size output, called a hash.
* **Cryptanalysis:** The study of how to break cryptographic systems.

<figure><img src="https://qph.cf2.quoracdn.net/main-qimg-a4901247ab679c2aec9e3f99a263788d-pjlq" alt=""><figcaption></figcaption></figure>

### <mark style="color:blue;">Multiple Encryption</mark>

Multiple encryption, also known as cascade encryption or superencryption, is the process of encrypting an already encrypted message one or more times, either using the same or a different algorithm.

There are a few reasons why someone might choose to use multiple encryption. One reason is to increase the security of the message. If an attacker is able to crack one layer of encryption, they will still need to crack the other layers in order to access the original message.

Another reason to use multiple encryption is to make it more difficult for attackers to analyze the message. If the message is encrypted multiple times, it will be more difficult for attackers to identify the encryption algorithm that is being used.

Finally, multiple encryption can be used to protect against different types of attacks. For example, one layer of encryption could be used to protect against brute-force attacks, while another layer of encryption could be used to protect against dictionary attacks.

Here are some examples of multiple encryption:

* **Encrypting a file with two different encryption algorithms.**
* **Encrypting a file with a single encryption algorithm and then storing the encrypted file on an encrypted hard drive.**
* **Encrypting an email message with S/MIME, which uses multiple encryption algorithms and digital signatures to protect the message.**

Multiple encryption can be a very effective way to protect sensitive data. However, it is important to note that it is not a silver bullet. If an attacker has enough resources and time, they may eventually be able to crack any encryption system.

### <mark style="color:blue;">**Applications of Cryptography**</mark>

Cryptography is used in a wide variety of applications, including:

* **Secure communication:** Cryptography is used to secure communication channels, such as email and instant messaging.
* **Data protection:** Cryptography is used to protect data that is stored on computers and other devices.
* **Financial transactions:** Cryptography is used to secure financial transactions, such as credit card payments and online banking.
* **Digital signatures:** Cryptography is used to create digital signatures, which can be used to verify the authenticity of digital messages and documents.

## Hash Algorithms

### <mark style="color:blue;">Overview</mark>

Hash algorithms are mathematical functions that take an input of any size and produce a fixed-size output, called a hash value. Hash functions are often used to check the integrity of data, as it is very difficult to find two different inputs that produce the same hash value.

Hash algorithms are also used in a variety of other applications, such as:

* **Digital signatures:** Hash functions can be used to create digital signatures, which can be used to verify the authenticity of a digital message or document.
* **Password storage:** Hash functions can be used to store passwords securely. When a user creates an account, their password is hashed and the hash value is stored instead of the plain text password. When the user logs in, their password is hashed again and compared to the stored hash value. If the two hash values match, the user is authenticated.
* **File integrity:** Hash functions can be used to check the integrity of files. When a file is downloaded, its hash value can be calculated and compared to the hash value of the original file. If the two hash values match, the file is considered to be intact.

Which hash algorithm to use depends on the specific needs of the situation. If you need a secure hash function for a security-critical application, you should use one of the latest SHA-3 algorithms. If you need a hash function for a less critical application, you may be able to use an older hash function, such as MD5 or SHA-1.

It is important to note that no hash algorithm is completely secure. Researchers are constantly working to find new ways to break hash algorithms. As a result, it is important to use the latest hash algorithms and to keep your systems up to date.

### <mark style="color:blue;">Hash Algorithms</mark>

#### <mark style="color:blue;">**MD5 Algorithm**</mark>

MD5, or Message-Digest Algorithm 5, is a cryptographic hash function that takes a variable-length input and produces a fixed-length 128-bit output. MD5 was developed in the early 1990s and was widely used for security applications, such as digital signatures and password storage. However, in recent years, MD5 has been shown to be vulnerable to collision attacks, which means that it is possible to find two different inputs that produce the same MD5 hash. As a result, MD5 is no longer considered to be a secure hash function and should not be used for any security-critical applications.

Here is a 50-word summary of the MD5 algorithm:

MD5 is a cryptographic hash function that takes a variable-length input and produces a fixed-length 128-bit output. It was widely used for security applications, such as digital signatures and password storage, but it is no longer considered to be secure and should not be used for any security-critical applications.

{% embed url="https://www.md5.cz/" %}

#### <mark style="color:blue;">SHA-1 Algorithm</mark>

SHA-1, or Secure Hash Algorithm 1, is a cryptographic hash function that takes a variable-length input and produces a fixed-length 160-bit output. SHA-1 was developed in the early 1990s and was widely used for security applications, such as digital signatures and file integrity checks. However, in recent years, SHA-1 has been shown to be vulnerable to collision attacks, which means that it is possible to find two different inputs that produce the same SHA-1 hash. As a result, SHA-1 is no longer considered to be a secure hash function and should not be used for any security-critical applications.

SHA-1 is still used in some applications today, but it is important to be aware of its security limitations. If you are using an application that uses SHA-1, you should upgrade to a newer algorithm if possible.

{% embed url="https://codebeautify.org/sha1-hash-generator" %}

#### <mark style="color:blue;">SHA-3 Algorithm</mark>

SHA-3, or Secure Hash Algorithm 3, is a cryptographic hash function that takes a variable-length input and produces a fixed-length 224-, 256-, 384-, or 512-bit output. SHA-3 was selected by NIST in 2015 to replace the SHA-2 family of hash functions, and it is now the recommended hash function for security-critical applications.

SHA-3 is based on the Keccak sponge algorithm, which is a very versatile and efficient cryptographic primitive. SHA-3 is resistant to all known attacks, and it is expected to remain secure for many years to come.

{% embed url="https://codebeautify.org/sha3-256-hash-generator" %}

#### <mark style="color:blue;">Other Algorithms</mark>

* MD2 Hash
* MD4 Hash
* NTLM Hash
* SHA1 Hash
* SHA224 Hash
* SHA256 Hash
* SHA384 Hash
* SHA512 Hash
* SHA512/224 Hash
* SHA512/256 Hash
* SHA3-224 Hash
* SHA3-256 Hash
* SHA3-384 Hash
* SHA3-512 Hash
* CRC-16 Hash
* CRC-32 Hash
* Shake-128 Hash
* Shake-256 Hash
* MD6 Hash
* Whirlpool Hash
* npemd128
* ripemd160
* ripemd256
* ripemd320
* liger160,3
* tiger128,3
* liger192,3
* Liger128,4
* Liger160,4
* tiger192,4
* snefru
* gost
* adlor32
* crc32
* crc32b
* haval128,3
* Mhaval160,3
* haval192,3
* haval224,3
* haval256,3,
* haval128,4
* haval 160,4
* haval192,4
* haval224,4
* haval256,4
* haval128,5
* haval160,5
* haval192,5
* haval224,5
* haval256,5

#### <mark style="color:blue;">Passwords Generator / Hash Generator</mark>

{% embed url="https://passwordsgenerator.net/sha1-hash-generator/" %}

### <mark style="color:blue;">Online Hash Cracking Tools</mark>

#### <mark style="color:blue;">Crackstation</mark>

Can crack LM, NTLM, md2, md4, md5, md5\_hex), md5-half, sha1, sha224, sha256, sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ , sha1\_bin Algorithms.

{% embed url="https://crackstation.net/" %}

#### <mark style="color:blue;">Online Hash Crack</mark>

{% embed url="https://www.onlinehashcrack.com/" %}

### <mark style="color:blue;">Hashcat</mark>

Hashcat is a popular password cracking tool that can be used to crack a wide variety of hash algorithms, including MD5, SHA-1, SHA-2, and SHA-3. Hashcat uses a variety of different techniques to crack hashes, including brute-force attacks, dictionary attacks, and mask attacks.

Hashcat is a very powerful tool, but it is important to use it responsibly. Hashcat should only be used to crack hashes that you have permission to crack. It is illegal to crack hashes without the permission of the owner of the hashes.

Hashcat can be used for both ethical and unethical purposes. It is important to be aware of the legal and ethical implications of using Hashcat before using it.

for more information you can check Hashcat paragraph/chapter:

{% embed url="https://youtu.be/-UrdExQW0cs" %}

## Steganography: Hiding Data in music and photos

### Overview <a href="#overview" id="overview"></a>

Steganography is the practice of concealing a secret message within a plain sight medium. In cryptography, steganography is used to hide a message within an ordinary message, file, or signal. Steganography is distinguished from cryptography by the fact that in steganography, the hidden message does not appear to be present in any way.

Steganography can be used for a variety of purposes, including:

* To communicate sensitive information without being detected.
* To hide data within other data, such as hiding a file within an image or a message within an audio file.
* To create watermarks to protect copyright.

{% embed url="https://www.youtube.com/watch?v=yq9zo6IzP64" %}
