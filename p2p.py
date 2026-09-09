import socket
import json

def obtener_ip_local():
    """Obtiene la IP local real de la interfaz de red."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# ==========================================
# ALGORITMOS MATEMÁTICOS
# ==========================================

def cifrado_cesar(texto, desplazamiento, modo="cifrar"):
    resultado = ""
    if modo == "descifrar":
        desplazamiento = -desplazamiento
    for caracter in texto:
        if caracter.isalpha():
            ascii_offset = 65 if caracter.isupper() else 97
            nuevo_caracter = chr((ord(caracter) - ascii_offset + desplazamiento) % 26 + ascii_offset)
            resultado += nuevo_caracter
        else:
            resultado += caracter
    return resultado

def cifrado_vigenere(texto, clave, modo="cifrar"):
    resultado = ""
    clave = clave.upper()
    indice_clave = 0
    for caracter in texto:
        if caracter.isalpha():
            ascii_offset = 65 if caracter.isupper() else 97
            desplazamiento = ord(clave[indice_clave % len(clave)]) - 65
            if modo == "descifrar":
                desplazamiento = -desplazamiento
            nuevo_caracter = chr((ord(caracter) - ascii_offset + desplazamiento) % 26 + ascii_offset)
            resultado += nuevo_caracter
            indice_clave += 1
        else:
            resultado += caracter
    return resultado

def procesar_vernam_char(letra, clave_binaria):
    indice_letra = ord(letra.upper()) - 65
    entero_clave = int(clave_binaria, 2)
    resultado_xor = indice_letra ^ entero_clave
    return {
        "binario_original": format(indice_letra, '05b'),
        "binario_xor": format(resultado_xor, '05b'),
        "decimal": resultado_xor,
        "letra_final": chr((resultado_xor % 26) + 65)
    }

# ==========================================
# LÓGICA DE RED: EMISOR (CLIENTE)
# ==========================================

def modo_emisor(ip_destino, puerto):
    print(f"\n[+] Iniciando Emisor...")
    try:
        cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente.connect((ip_destino, puerto))
        print(f"[EXITO] Conexión TCP establecida con {ip_destino}:{puerto}")
        
        print("\n[1] Selecciona la operación a realizar:")
        print("    A) Cifrado César")
        print("    B) Cifrado Vigenère")
        print("    C) Cifrado Vernam (1 Letra / XOR)")
        print("    D) Intercambio de Llaves (Diffie-Hellman)")
        print("    E) Cifrado Asimétrico (RSA Text-book)")
        opcion_alg = input("Opción: ").upper()
        
        payload = {}
        
        if opcion_alg in ['A', 'B']:
            mensaje_plano = input("[2] Ingresa el mensaje en texto plano: ")
            if opcion_alg == 'A':
                desplazamiento = int(input("[3] Ingresa la clave numérica (desplazamiento): "))
                payload = {"algoritmo": "CESAR", "datos": cifrado_cesar(mensaje_plano, desplazamiento)}
            else:
                clave_texto = input("[3] Ingresa la palabra clave (ej. SECRETO): ")
                payload = {"algoritmo": "VIGENERE", "datos": cifrado_vigenere(mensaje_plano, clave_texto)}
                
        elif opcion_alg == 'C':
            letra_plana = input("[2] Ingresa UNA sola letra (ej. T): ").upper()
            while len(letra_plana) != 1 or not letra_plana.isalpha():
                letra_plana = input("Error. Ingresa exactamente UNA letra (A-Z): ").upper()
                
            clave_bin = input("[3] Ingresa clave binaria de 5 bits (ej. 01010): ")
            while len(clave_bin) != 5 or not all(c in '01' for c in clave_bin):
                clave_bin = input("Error. Ingresa exactamente 5 bits (0 y 1): ")
                
            payload = {"algoritmo": "VERNAM", "datos": procesar_vernam_char(letra_plana, clave_bin)}
            
        elif opcion_alg == 'D':
            print("\n--- Diffie-Hellman ---")
            P = int(input("Ingresa el número primo público (P): "))
            G = int(input("Ingresa la base pública (G): "))
            a = int(input("Ingresa tu clave privada secreta (a): "))
            payload = {"algoritmo": "DIFFIE", "P": P, "G": G, "llave_publica_A": pow(G, a, P)}
            
        elif opcion_alg == 'E':
            # Fase 1: Petición de Llave Pública
            cliente.send(json.dumps({"algoritmo": "RSA_REQ"}).encode('utf-8'))
            print("\n[INFO] Solicitando Llave Pública al Receptor...")
            
            resp_cruda = cliente.recv(1024).decode('utf-8')
            llaves = json.loads(resp_cruda)
            e_pub = llaves.get("e")
            n_pub = llaves.get("n")
            print(f"[EXITO] Llave Pública recibida desde la red: e={e_pub}, n={n_pub}")
            
            # Fase 2: Cifrado y envío
            mensaje_plano = input("\n[2] Ingresa el mensaje en texto plano (ej. YESTERDAY): ")
            mensaje_cifrado = [pow(ord(char), e_pub, n_pub) for char in mensaje_plano]
            payload = {"algoritmo": "RSA_DATA", "datos": mensaje_cifrado}
            
        # Envío general de payloads a través del socket
        if payload:
            bytes_enviados = cliente.send(json.dumps(payload).encode('utf-8'))
            print(f"\n[INFO] Transmisión completada. ({bytes_enviados} bytes)")
            
            # Espera de respuesta para Diffie-Hellman
            if opcion_alg == 'D':
                print("[INFO] Esperando respuesta del receptor (Llave B)...")
                respuesta = json.loads(cliente.recv(1024).decode('utf-8'))
                B = respuesta.get("llave_publica_B")
                print(f"[EXITO] Llave pública 'B' recibida: {B}")
                secreto_compartido = pow(B, a, P)
                print(f"\n" + "*"*45)
                print(f" [!] SECRETO COMPARTIDO CALCULADO: {secreto_compartido} [!]")
                print("*"*45 + "\n")
                
        else:
            print("[!] Opción no válida.")
            
        cliente.close()
    except Exception as e:
        print(f"[ERROR] Ocurrió un problema de red: {e}")

# ==========================================
# LÓGICA DE RED: RECEPTOR (SERVIDOR)
# ==========================================

def modo_receptor(puerto):
    ip_local = obtener_ip_local()
    print(f"\n[+] Iniciando Receptor en {ip_local}:{puerto}...")
    
    try:
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.bind(('0.0.0.0', puerto)) 
        servidor.listen(1) 
        
        print("[INFO] Esperando conexión entrante...")
        conexion, direccion = servidor.accept() 
        print(f"\n[EXITO] Conexión aceptada desde {direccion[0]}:{direccion[1]}")
        
        # Buffer amplio (4096) para asegurar que quepan las matrices de RSA
        datos_crudos = conexion.recv(4096).decode('utf-8')
        
        if datos_crudos:
            paquete = json.loads(datos_crudos)
            algoritmo_usado = paquete.get("algoritmo")
            
            print(f"\n--- PAQUETE RECIBIDO ---")
            print(f"[ALGORITMO DETECTADO]: {algoritmo_usado}")
            
            # --- Flujo RSA ---
            if algoritmo_usado == "RSA_REQ":
                print("\n[!] El Emisor solicita iniciar una sesión RSA.")
                p = int(input("Ingresa el número primo 'p' (ej. 17): "))
                q = int(input("Ingresa el número primo 'q' (ej. 31): "))
                n = p * q
                phi = (p - 1) * (q - 1)
                print(f" -> Valor Phi (φ) de Euler calculado: {phi}")
                
                e = int(input(f"Ingresa el exponente público 'e' (coprimo de {phi}, ej. 7): "))
                d = pow(e, -1, phi) 
                print(f" -> Tu Llave Privada generada es (d): {d}")
                
                # Enviar Llave Pública al Emisor
                conexion.send(json.dumps({"e": e, "n": n}).encode('utf-8'))
                print("[INFO] Llave Pública enviada. Esperando matriz de datos cifrados...")
                
                # Recibir datos cifrados
                paquete_datos = json.loads(conexion.recv(4096).decode('utf-8'))
                datos_recibidos = paquete_datos.get("datos")
                
                print(f"\n[MATRIZ NUMÉRICA CIFRADA]: {datos_recibidos}")
                
                resp = input("\n¿Deseas descifrar el mensaje? (s/n): ").lower()
                if resp == 's':
                    d_intentada = int(input("Ingresa tu exponente privado (d): "))
                    descifrado_ascii = [pow(num, d_intentada, n) for num in datos_recibidos]
                    mensaje_descifrado = "".join([chr(num) for num in descifrado_ascii])
                    print(f"\n[RESULTADO] Mensaje reconstruido: {mensaje_descifrado}")

            # --- Flujo Diffie-Hellman ---
            elif algoritmo_usado == "DIFFIE":
                P = paquete.get("P")
                G = paquete.get("G")
                A = paquete.get("llave_publica_A")
                
                print(f" -> Parámetros públicos: P={P}, G={G}")
                print(f" -> Llave pública del Emisor (A) recibida: {A}")
                
                b = int(input("\n[!] Ingresa tu clave privada secreta (b): "))
                B = pow(G, b, P)
                
                respuesta = {"llave_publica_B": B}
                conexion.send(json.dumps(respuesta).encode('utf-8'))
                print(f"[INFO] Tu llave pública 'B' ({B}) ha sido enviada al emisor.")
                
                secreto_compartido = pow(A, b, P)
                print(f"\n" + "*"*45)
                print(f" [!] SECRETO COMPARTIDO CALCULADO: {secreto_compartido} [!]")
                print("*"*45 + "\n")
                
            # --- Flujos Simétricos (César, Vigenère, Vernam) ---
            else:
                datos_recibidos = paquete.get("datos")
                if algoritmo_usado == "VERNAM":
                    print(f"[MENSAJE CIFRADO]: {datos_recibidos['letra_final']}")
                    print(f" -> Log de bits (XOR): {datos_recibidos['binario_xor']}")
                else:
                    print(f"[MENSAJE CIFRADO]: {datos_recibidos}")
                
                resp = input("\n¿Deseas descifrar el mensaje? (s/n): ").lower()
                if resp == 's':
                    if algoritmo_usado == "CESAR":
                        clave_intentada = int(input("Ingresa la clave numérica de desplazamiento: "))
                        print(f"\n[RESULTADO]: {cifrado_cesar(datos_recibidos, clave_intentada, modo='descifrar')}")
                        
                    elif algoritmo_usado == "VIGENERE":
                        clave_intentada = input("Ingresa la palabra clave: ")
                        print(f"\n[RESULTADO]: {cifrado_vigenere(datos_recibidos, clave_intentada, modo='descifrar')}")
                        
                    elif algoritmo_usado == "VERNAM":
                        clave_intentada = input("Ingresa la clave binaria de 5 bits original: ")
                        resultado = procesar_vernam_char(datos_recibidos['letra_final'], clave_intentada)
                        print(f"\n[RESULTADO]: Letra original descifrada: {resultado['letra_final']}")
        
        conexion.close()
        servidor.close()
    except Exception as e:
        print(f"[ERROR] Ocurrió un problema en el receptor: {e}")

# ==========================================
# PUNTO DE ENTRADA PRINCIPAL
# ==========================================

def main():
    while True: 
        print("\n" + "="*50)
        print("   HERRAMIENTA P2P: CRIPTOGRAFÍA Y REDES")
        print("="*50)
        rol = input("Selecciona tu rol (1: Emisor, 2: Receptor, 3: Salir): ")
        
        if rol == '1':
            ip = input("Ingresa la IP privada del Receptor: ")
            modo_emisor(ip, 8080)
        elif rol == '2':
            modo_receptor(8080)
        elif rol == '3':
            print("Cerrando la aplicación. ¡Hasta pronto!")
            break
        else:
            print("[!] Opción inválida. Intenta nuevamente.")

if __name__ == "__main__":
    main()