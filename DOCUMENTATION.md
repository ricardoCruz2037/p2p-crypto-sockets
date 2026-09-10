# Technical Documentation: P2P Crypto Sockets

## 1. Technology Stack

* **Language:** Python 3.x
* **Networking:** `socket` (TCP/IPv4 standard library)
* **Serialization:** `json` (Application-layer payload formatting)
* **Validation:** `re` (Regular expressions for input sanitization)

## 2. Network Connection Architecture

The application operates on a Peer-to-Peer (P2P) model using TCP over IPv4.

* **Protocol:** TCP (Transmission Control Protocol) ensures reliable, ordered, and error-checked delivery of streams.
* **Port:** 8080 (Default).
* **Socket Configuration:** The receiver implements `SO_REUSEADDR` to bypass the TCP `TIME_WAIT` state. This prevents the `[Errno 98] Address already in use` exception, allowing immediate port rebinding after a session terminates.

```python
servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
servidor.bind(('0.0.0.0', 8080))
```

**Data Encapsulation:** Data is transmitted as UTF-8 encoded byte streams structured in JSON format. This simulates a Layer 7 Protocol Data Unit (PDU).

```json
{
  "algoritmo": "CESAR",
  "datos": "UHG"
}
```

## 3. Code Structure

The script `p2p.py` is divided into four main logical blocks:

1. **Validation & Control:** Functions (`validar_ip`, `pedir_entero`, `pedir_texto_alfabetico`) to enforce strict input requirements and prevent runtime exceptions.
2. **Mathematical Algorithms:** Core cryptographic logic isolated into independent functions.
3. **Emitter Logic (Client):** Initiates the TCP connection, captures user input, serializes the payload, and manages the transmission state.
4. **Receiver Logic (Server):** Binds the listening port, deserializes incoming JSON payloads, detects the algorithm flag, and executes decryption.

## 4. Implemented Algorithms & Examples

### 4.1 Caesar Cipher (Symmetric)

A monoalphabetic substitution cipher that shifts characters by a fixed numeric offset.

**Mathematical Formula:**

$$C_i = (P_i + K) \pmod{26}$$

**Example:**

* Plaintext ($P$): `RED`
* Key ($K$): `3`
* Process:
  * R(17) + 3 = 20 → U
  * E(4) + 3 = 7 → H
  * D(3) + 3 = 6 → G
* Ciphertext ($C$): `UHG`

### 4.2 Vigenère Cipher (Symmetric)

A polyalphabetic substitution cipher that uses a keyword to determine varying shifts.

**Mathematical Formula:**

$$C_i = (P_i + K_i) \pmod{26}$$

**Example:**

* Plaintext ($P$): `RED`
* Keyword ($K$): `KEY`
* Process:
  * R(17) + K(10) = 27 → 27 mod 26 = 1 → B
  * E(4) + E(4) = 8 → 8 mod 26 = 8 → I
  * D(3) + Y(24) = 27 → 27 mod 26 = 1 → B
* Ciphertext ($C$): `BIB`

### 4.3 Vernam Cipher / XOR (Symmetric)

Operates at the bit level utilizing the XOR ($\oplus$) logic gate.

**Mathematical Formula:**

$$C = P \oplus K$$

**Example:**

* Plaintext ($P$): `T` (Index 19, Binary: `10011`)
* Binary Key ($K$): `01010`
* Process: `10011 XOR 01010 = 11001`
* Ciphertext ($C$): Decimal 25, which corresponds to `Z`

### 4.4 Diffie-Hellman (Asymmetric Key Exchange)

Allows two nodes to generate a shared secret over an insecure channel. It does not encrypt data; it agrees on a key.

**Mathematical Formula:**

* Public Keys: $A = G^a \pmod P$ and $B = G^b \pmod P$
* Shared Secret: $S = B^a \pmod P = A^b \pmod P$

**Example:**

* Public Parameters: $P = 23$ (Prime), $G = 5$ (Base)
* Emitter Private Key ($a$): `6`
* Receiver Private Key ($b$): `15`
* Emitter computes $A$: $5^6 \pmod{23} = 8$
* Receiver computes $B$: $5^{15} \pmod{23} = 19$
* Emitter computes Secret: $19^6 \pmod{23} = 2$
* Receiver computes Secret: $8^{15} \pmod{23} = 2$
* Shared Secret ($S$): `2`

### 4.5 RSA Textbook (Asymmetric Cryptography)

Utilizes a public key for encryption and a private key for decryption based on prime factorization. The script processes strings by converting them to their ASCII decimal equivalents before applying the formula.

**Mathematical Formula:**

* Modulus: $n = p \times q$
* Totient: $\phi = (p-1)(q-1)$
* Encryption: $C = M^e \pmod n$
* Decryption: $M = C^d \pmod n$

**Example:**

* Receiver Configuration: $p = 17$, $q = 31$ → $n = 527$, $\phi = 480$
* Exponents: Public ($e$) = `7`. Private ($d$) = `343`.
* Plaintext Letter ($M$): `Y` (ASCII value: 89)
* Encryption (Emitter): $89^7 \pmod{527} = 387$
* Transmitted Ciphertext ($C$): `[387]`
* Decryption (Receiver): $387^{343} \pmod{527} = 89$ (ASCII `Y`)