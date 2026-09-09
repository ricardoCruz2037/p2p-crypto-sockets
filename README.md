# P2P Crypto Sockets 🔐

A lightweight, Python-based CLI application designed to demonstrate the fundamentals of network security, cryptography, and raw socket programming. 

This project establishes a direct Peer-to-Peer (P2P) connection over TCP between two devices on the same local network, allowing them to exchange payloads using various symmetric and asymmetric cryptographic algorithms. It is built as a hands-on laboratory tool for understanding how data is transformed and transmitted across network layers.

## 🚀 Overview and Purpose
This project bridges the gap between theoretical cryptography and practical network engineering. Instead of using high-level libraries that obscure the underlying mechanics, this tool uses raw TCP sockets and mathematical implementations to show exactly how encrypted bytes travel through a network.

**Key Learning Objectives:**
* **Transport Layer Manipulation:** Understanding the 3-way TCP handshake and socket binding across different operating systems (e.g., Linux and Windows).
* **Protocol Data Units (PDUs):** Structuring application-layer payloads using JSON to transmit both metadata (algorithm flags, public keys) and the encrypted data.
* **Applied Cryptography:** Transitioning from simple monoalphabetic substitution to complex modular arithmetic used in modern Public Key Infrastructure (PKI).

## 🛠️ Features & Implemented Algorithms
The application features an interactive menu to act as either the **Sender (Client)** or the **Receiver (Server)**. 

### Symmetric Cryptography (Confidentiality)
* **Caesar Cipher:** Monoalphabetic substitution using a numeric shift key.
* **Vigenère Cipher:** Polyalphabetic substitution using a string-based keyword.
* **Vernam Cipher (XOR):** Perfect secrecy implementation manipulating bits. The tool takes a single character, applies a 5-bit binary key via XOR logic, and transmits the resulting data.

### Asymmetric Cryptography (Key Exchange & PKI)
* **Diffie-Hellman Key Exchange:** Allows two nodes to mathematically agree on a shared secret over an insecure TCP channel without ever transmitting the secret itself.
* **Textbook RSA:** A foundational implementation of RSA. The Receiver generates public/private keys using small prime numbers (p, q), sends the Public Key (e, n) over the network, and the Sender uses it to encrypt an ASCII array block by block.

## 💻 Technology Stack
* **Language:** Python 3.x
* **Networking:** `socket` (Native library for IPv4, TCP streaming)
* **Data Serialization:** `json` (For payload structuring)

## ⚙️ How it Works (Architecture)
1. **Connection:** The Receiver binds a TCP socket to `0.0.0.0:8080` and listens. The Sender targets the Receiver's private IP to establish a connection.
2. **Payload Generation:** The user selects an algorithm and inputs plaintext. The text is encrypted locally.
3. **Transmission:** The payload is packaged into a JSON object (e.g., `{"algoritmo": "CESAR", "datos": "KROD"}`) and sent over the network as a UTF-8 encoded byte stream.
4. **Reception & Decryption:** The Receiver decodes the JSON, reads the metadata flag, and prompts the user to enter the corresponding decryption key or private mathematical exponent to reconstruct the plaintext.

## 📥 Getting Started (Laboratory Setup)

### Prerequisites
* Python 3 installed on both devices.
* Both devices must be on the same Local Area Network (LAN).
* Ensure your firewall (e.g., Windows Defender Firewall, firewalld) allows inbound traffic on TCP port `8080`.

### Execution
1. Clone the repository to both machines.
   ```bash
   git clone [https://github.com/ricardoCruz2037/p2p-crypto-sockets.git](https://github.com/ricardoCruz2037/p2p-crypto-sockets.git)
   cd p2p-crypto-sockets
    ```
2. On the Receiving Machine:
    Run the script and select option 2.
   ```bash
    python p2p.py
   ```
   Note the Local IP address displayed in the terminal.

3. On the Sending Machine:
    Run the script, select option 1, and enter the Receiver's IP address when prompted.

## 🗺️ Roadmap & Future Versions

* **V1.1 (Current):** Concept validation, pure Python socket implementation across local Linux/Windows environments.
* **V2.0:** Migration from standard Wi-Fi testing to isolated VLANs using physical routing infrastructure (e.g., Cisco routers), implementing ACLs to filter the application's traffic.
* **V3.0:** Integration of industry-standard AES (Advanced Encryption Standard) block ciphers using the cryptography library for modern security compliance.
  
## 👨‍💻 Author
**Richard**
Information and Communications Technology Engineering Student
Focusing on NetDevOps, Cloud Infrastructure, and Network Security.
