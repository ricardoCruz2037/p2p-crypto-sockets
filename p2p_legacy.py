import socket
import json
import re

# ==========================================
# VALIDATION AND CONTROL FUNCTIONS
# ==========================================

def get_local_ip():
    """Obtains the real local IP of the network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def validate_ip(ip_address):
    """Verifies that the entered string is a valid IPv4 address."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(pattern, ip_address):
        return all(0 <= int(octet) <= 255 for octet in ip_address.split('.'))
    return False

def request_integer(prompt_message):
    """Ensures the user strictly enters an integer."""
    while True:
        try:
            return int(input(prompt_message))
        except ValueError:
            print("[!] Error: Invalid input. You must enter an integer.")

def request_alphabetic_text(prompt_message, allow_spaces=True):
    """Ensures the entered text does not contain numbers or special characters."""
    while True:
        text = input(prompt_message)
        # Check by temporarily removing spaces if they are allowed
        check_text = text.replace(" ", "") if allow_spaces else text
        if check_text.isalpha():
            return text
        print("[!] Error: Strict format. Only letters are allowed (no numbers or symbols).")

# ==========================================
# MATHEMATICAL ALGORITHMS
# ==========================================

def caesar_cipher(text, shift, mode="encrypt"):
    result = ""
    if mode == "decrypt":
        shift = -shift
        
    for character in text:
        if character.isalpha():
            ascii_offset = 65 if character.isupper() else 97
            new_character = chr((ord(character) - ascii_offset + shift) % 26 + ascii_offset)
            result += new_character
        else:
            result += character
    return result

def vigenere_cipher(text, key, mode="encrypt"):
    result = ""
    key = key.upper()
    key_index = 0
    
    for character in text:
        if character.isalpha():
            ascii_offset = 65 if character.isupper() else 97
            shift = ord(key[key_index % len(key)]) - 65
            if mode == "decrypt":
                shift = -shift
            new_character = chr((ord(character) - ascii_offset + shift) % 26 + ascii_offset)
            result += new_character
            key_index += 1
        else:
            result += character
    return result

def process_vernam_char(letter, binary_key):
    letter_index = ord(letter.upper()) - 65
    key_integer = int(binary_key, 2)
    xor_result = letter_index ^ key_integer
    
    return {
        "original_binary": format(letter_index, '05b'),
        "xor_binary": format(xor_result, '05b'),
        "decimal": xor_result,
        "final_letter": chr((xor_result % 26) + 65)
    }

# ==========================================
# NETWORK LOGIC: SENDER (CLIENT)
# ==========================================

def sender_mode(target_ip, port):
    print(f"\n[+] Starting Sender... Attempting to connect to {target_ip}:{port}")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_ip, port))
        print(f"[SUCCESS] Persistent TCP session established.")
        
        while True:
            print("\n" + "-"*35)
            print(" [1] Select operation to perform:")
            print("    A) Caesar Cipher")
            print("    B) Vigenère Cipher")
            print("    C) Vernam Cipher (1 Letter / XOR)")
            print("    D) Key Exchange (Diffie-Hellman)")
            print("    E) Asymmetric Cipher (RSA Textbook)")
            print("    S) End session and disconnect")
            print("-" * 35)
            algorithm_option = input("Option: ").upper()
            
            payload = {}
            
            if algorithm_option == 'S':
                print("[INFO] Closing TCP session safely...")
                client.send(json.dumps({"algorithm": "EXIT"}).encode('utf-8'))
                break 
                
            elif algorithm_option not in ['A', 'B', 'C', 'D', 'E']:
                print("[!] Invalid option. Try again.")
                continue 
            
            if algorithm_option in ['A', 'B']:
                plaintext = request_alphabetic_text("[2] Enter plaintext message: ")
                if algorithm_option == 'A':
                    shift = request_integer("[3] Enter numeric shift key: ")
                    payload = {"algorithm": "CAESAR", "data": caesar_cipher(plaintext, shift)}
                else:
                    text_key = request_alphabetic_text("[3] Enter keyword: ", allow_spaces=False)
                    payload = {"algorithm": "VIGENERE", "data": vigenere_cipher(plaintext, text_key)}
                    
            elif algorithm_option == 'C':
                plaintext_letter = request_alphabetic_text("[2] Enter ONE single letter: ", allow_spaces=False).upper()
                while len(plaintext_letter) != 1:
                    print("Error. Enter exactly ONE letter.")
                    plaintext_letter = request_alphabetic_text("Letter: ", allow_spaces=False).upper()
                    
                binary_key = input("[3] Enter 5-bit binary key: ")
                while len(binary_key) != 5 or not all(c in '01' for c in binary_key):
                    binary_key = input("Error. Enter exactly 5 bits (0 and 1): ")
                    
                payload = {"algorithm": "VERNAM", "data": process_vernam_char(plaintext_letter, binary_key)}
                
            elif algorithm_option == 'D':
                print("\n--- Diffie-Hellman ---")
                public_p = request_integer("[2] Enter public prime number (P): ")
                public_g = request_integer("[3] Enter public base (G): ")
                private_a = request_integer("[4] Enter your private secret key (a): ")
                payload = {"algorithm": "DIFFIE", "P": public_p, "G": public_g, "public_key_A": pow(public_g, private_a, public_p)}
                
            elif algorithm_option == 'E':
                client.send(json.dumps({"algorithm": "RSA_REQ"}).encode('utf-8'))
                print("\n[INFO] Requesting Public Key from Receiver...")
                
                raw_response = client.recv(1024).decode('utf-8')
                keys = json.loads(raw_response)
                public_e = keys.get("e")
                public_n = keys.get("n")
                print(f"[SUCCESS] Public Key received from network: e={public_e}, n={public_n}")
                
                plaintext = request_alphabetic_text("\n[2] Enter plaintext message: ")
                ciphertext = [pow(ord(char), public_e, public_n) for char in plaintext]
                payload = {"algorithm": "RSA_DATA", "data": ciphertext}
                
            # General payload transmission
            if payload:
                sent_bytes = client.send(json.dumps(payload).encode('utf-8'))
                print(f"\n[INFO] Data transmission completed. ({sent_bytes} bytes)")
                
                if algorithm_option == 'D':
                    print("[INFO] Waiting for receiver's response (Key B)...")
                    response = json.loads(client.recv(1024).decode('utf-8'))
                    public_b = response.get("public_key_B")
                    print(f"[SUCCESS] Public key 'B' received: {public_b}")
                    shared_secret = pow(public_b, private_a, public_p)
                    print(f"\n" + "*"*45)
                    print(f" [!] CALCULATED SHARED SECRET: {shared_secret} [!]")
                    print("*"*45 + "\n")
                    
        client.close()
        print("[SUCCESS] Sender disconnected successfully.")
    except Exception as e:
        print(f"\n[ERROR] A network issue occurred: {e}")

# ==========================================
# NETWORK LOGIC: RECEIVER (SERVER)
# ==========================================

def receiver_mode(port):
    local_ip = get_local_ip()
    print(f"\n[+] Starting Receiver at {local_ip}:{port}...")
    
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # [FIX] SO_REUSEADDR configuration to prevent 'Address already in use' (TIME_WAIT) error
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        server.bind(('0.0.0.0', port)) 
        server.listen(1) 
        
        print("[INFO] Waiting for incoming connection...")
        connection, address = server.accept() 
        print(f"\n[SUCCESS] Active connection initiated from {address[0]}:{address[1]}")
        
        while True:
            raw_data = connection.recv(4096).decode('utf-8')
            
            if not raw_data:
                print("\n[!] Connection was unexpectedly interrupted by the sender.")
                break
                
            packet = json.loads(raw_data)
            used_algorithm = packet.get("algorithm")
            
            if used_algorithm == "EXIT":
                print("\n[INFO] Sender requested to close the session. Disconnecting...")
                break
                
            print(f"\n--- RECEIVED PACKET ---")
            print(f"[ALGORITHM DETECTED]: {used_algorithm}")
            
            # --- RSA Flow ---
            if used_algorithm == "RSA_REQ":
                print("\n[!] Sender requests to start an RSA session.")
                prime_p = request_integer("[1] Enter prime number 'p': ")
                prime_q = request_integer("[2] Enter prime number 'q': ")
                modulus_n = prime_p * prime_q
                phi = (prime_p - 1) * (prime_q - 1)
                print(f" -> Calculated Euler's Totient (φ): {phi}")
                
                public_e = request_integer(f"[3] Enter public exponent 'e' (coprime to {phi}): ")
                private_d = pow(public_e, -1, phi) 
                print(f" -> Your generated Private Key (d) is: {private_d}")
                
                connection.send(json.dumps({"e": public_e, "n": modulus_n}).encode('utf-8'))
                print("[INFO] Public Key sent. Waiting for encrypted data matrix...")
                
                data_packet = json.loads(connection.recv(4096).decode('utf-8'))
                received_data = data_packet.get("data")
                
                print(f"\n[ENCRYPTED NUMERIC MATRIX RECEIVED]: {received_data}")
                
                decrypt_response = input("\nDo you want to decrypt the message? (y/n): ").lower()
                if decrypt_response == 'y':
                    attempted_d = request_integer("[1] Enter your private exponent (d): ")
                    ascii_decrypted = [pow(num, attempted_d, modulus_n) for num in received_data]
                    decrypted_message = "".join([chr(num) for num in ascii_decrypted])
                    print(f"\n[RESULT] Reconstructed message: {decrypted_message}")

            # --- Diffie-Hellman Flow ---
            elif used_algorithm == "DIFFIE":
                public_p = packet.get("P")
                public_g = packet.get("G")
                public_a = packet.get("public_key_A")
                
                print(f" -> Public parameters: P={public_p}, G={public_g}")
                print(f" -> Sender's public key (A) received: {public_a}")
                
                private_b = request_integer("\n[1] Enter your private secret key (b): ")
                public_b = pow(public_g, private_b, public_p)
                
                response = {"public_key_B": public_b}
                connection.send(json.dumps(response).encode('utf-8'))
                print(f"[INFO] Your public key 'B' ({public_b}) has been sent to the sender.")
                
                shared_secret = pow(public_a, private_b, public_p)
                print(f"\n" + "*"*45)
                print(f" [!] CALCULATED SHARED SECRET: {shared_secret} [!]")
                print("*"*45 + "\n")
                
            # --- Symmetric Flows (Caesar, Vigenère, Vernam) ---
            else:
                received_data = packet.get("data")
                if used_algorithm == "VERNAM":
                    print(f"[ENCRYPTED MESSAGE]: {received_data['final_letter']}")
                    print(f" -> Bit log (XOR): {received_data['xor_binary']}")
                else:
                    print(f"[ENCRYPTED MESSAGE]: {received_data}")
                
                decrypt_response = input("\nDo you want to decrypt the message? (y/n): ").lower()
                if decrypt_response == 'y':
                    if used_algorithm == "CAESAR":
                        attempted_key = request_integer("[1] Enter numeric shift key: ")
                        print(f"\n[RESULT]: {caesar_cipher(received_data, attempted_key, mode='decrypt')}")
                        
                    elif used_algorithm == "VIGENERE":
                        attempted_key = request_alphabetic_text("[1] Enter keyword: ", allow_spaces=False)
                        print(f"\n[RESULT]: {vigenere_cipher(received_data, attempted_key, mode='decrypt')}")
                        
                    elif used_algorithm == "VERNAM":
                        attempted_key = input("[1] Enter original 5-bit binary key: ")
                        result = process_vernam_char(received_data['final_letter'], attempted_key)
                        print(f"\n[RESULT]: Original decrypted letter: {result['final_letter']}")
                        
            print("\n[INFO] Waiting for new instructions from sender...")
        
        connection.close()
        server.close()
        print("[SUCCESS] Receiver disconnected and ports released.")
    except Exception as e:
        print(f"\n[ERROR] An issue occurred in the receiver: {e}")
        try:
            connection.close()
        except:
            pass
        try:
            server.close()
        except:
            pass

# ==========================================
# MAIN ENTRY POINT
# ==========================================

def main():
    while True: 
        print("\n" + "="*50)
        print("   P2P TOOL: CRYPTOGRAPHY AND NETWORKING")
        print("="*50)
        role = input("Select your role (1: Sender, 2: Receiver, 3: Exit): ")
        
        if role == '1':
            while True:
                ip_address = input("Enter Receiver's private IP: ")
                if validate_ip(ip_address):
                    break
                print("[!] Error: You must enter a valid IP format.")
            sender_mode(ip_address, 8080)
            
        elif role == '2':
            receiver_mode(8080)
            
        elif role == '3':
            print("Closing the application. See you later!")
            break
            
        else:
            print("[!] Invalid option. Try again.")

if __name__ == "__main__":
    main()