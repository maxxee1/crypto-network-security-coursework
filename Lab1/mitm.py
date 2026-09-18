"""Actividad 3 - MitM (recuperar el mensaje del canal ICMP encubierto).

Lee los paquetes ICMP Echo Request generados por stealth.py (desde un pcap
o capturando en vivo), extrae el caracter escondido en cada uno (primer byte
del payload = bit/byte cambiado), reconstruye el texto CIFRADO y, como no se
conoce el corrimiento, prueba los 26 posibles y los imprime todos, resaltando
en VERDE la opcion mas probable de ser el mensaje en claro.

Fin de mensaje (sentinela 'b', segun el enunciado): el ULTIMO caracter
transmitido es la sentinela. OJO: la 'b' tambien aparece dentro del cifrado
(ej.: 'seguridad'->'bnpdarmjm'), asi que NO se puede cortar en la primera 'b'
o el mensaje se trunca. Por eso se leen TODOS los caracteres del canal y se
descarta solo la sentinela final.

Seleccion de la opcion mas probable: se combina
  (a) un puntaje por palabras frecuentes del espanol (peso alto), y
  (b) la distancia chi-cuadrado del histograma de letras respecto a la
      frecuencia del espanol (peso robusto para textos sin palabras claras).

Uso:
  python3 mitm.py --pcap salida.pcap
  sudo python3 mitm.py --sniff --iface en0     # captura en vivo
"""
import argparse

from scapy.all import rdpcap, sniff, ICMP, Raw

from cesar import cifrar_cesar


def descifrar_cesar(texto, corrimiento):
    """Descifra invirtiendo el corrimiento (reutiliza cifrar_cesar de la Act.1)."""
    return cifrar_cesar(texto, -corrimiento)


SENTINEL = "b"
VERDE = "\033[92m"
RESET = "\033[0m"

# Palabras frecuentes del espanol para puntuar cual descifrado es "texto real".
PALABRAS_ES = [
    " el ", " la ", " los ", " las ", " de ", " que ", " en ", " un ", " una ",
    " por ", " con ", " para ", " no ", " es ", " se ", " su ", " del ", " al ",
    " y ", " a ", " o ", " lo ", " le ", " mi ", " tu ", " si ", " ya ", " este ",
    "cion", "ado", "ada", "aba", "ente", "mente", "ando", "iendo",
    "mensaje", "secreto", "clave", "password", "hola", "informacion",
    "confidencial", "ataque", "amanecer", "seguridad", "redes", "criptografia",
]

# Frecuencia (%) de letras del espanol; base para el chi-cuadrado.
FREC_ES = {
    "a": 12.53, "b": 1.42, "c": 4.68, "d": 5.86, "e": 13.68, "f": 0.69,
    "g": 1.01, "h": 0.70, "i": 6.25, "j": 0.44, "k": 0.02, "l": 4.97,
    "m": 3.15, "n": 6.71, "o": 8.68, "p": 2.51, "q": 0.88, "r": 6.87,
    "s": 7.98, "t": 4.63, "u": 3.93, "v": 0.90, "w": 0.02, "x": 0.22,
    "y": 0.90, "z": 0.52,
}


def extraer_caracteres(paquetes):
    """De cada Echo Request toma data[0] (byte cambiado) y arma TODO el cifrado.

    La sentinela es el ULTIMO caracter, no la primera 'b': se leen todos los
    paquetes y se descarta unicamente la sentinela final (si esta presente)."""
    chars = []
    for pkt in paquetes:
        if ICMP in pkt and pkt[ICMP].type == 8 and Raw in pkt:
            chars.append(chr(bytes(pkt[Raw].load)[0]))
    if chars and chars[-1] == SENTINEL:   # descarta solo la sentinela final
        chars.pop()
    return "".join(chars)


def puntuar(texto):
    """Puntaje: mas alto = mas parecido a espanol real.

      palabras*100  (senal fuerte cuando hay palabras comunes)
      - chi2        (distancia a la frecuencia del espanol; robusto sin palabras)
    """
    t = " " + texto.lower() + " "
    palabras = sum(t.count(p) for p in PALABRAS_ES)

    # Chi-cuadrado del histograma de letras vs frecuencia del espanol.
    letras = [c for c in texto.lower() if c.isalpha()]
    n = len(letras) or 1
    conteo = {c: 0 for c in FREC_ES}
    for c in letras:
        if c in conteo:
            conteo[c] += 1
    chi2 = 0.0
    for c, frec in FREC_ES.items():
        esperado = frec / 100.0 * n
        if esperado > 0:
            chi2 += (conteo[c] - esperado) ** 2 / esperado

    return palabras * 100 - chi2


def main():
    p = argparse.ArgumentParser(description="MitM: rompe el Cesar del canal ICMP.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="Archivo .pcap con los paquetes capturados")
    src.add_argument("--sniff", action="store_true", help="Capturar en vivo (root)")
    p.add_argument("--iface", help="Interfaz para --sniff (ej: en0, eth0)")
    p.add_argument("--count", type=int, default=0, help="Nro de paquetes a capturar (0 = hasta Ctrl-C)")
    args = p.parse_args()

    if args.pcap:
        paquetes = rdpcap(args.pcap)
    else:
        print("[*] Capturando ICMP en vivo... (Ctrl-C para terminar)")
        paquetes = sniff(iface=args.iface, filter="icmp", count=args.count or 0)

    cifrado = extraer_caracteres(paquetes)
    print(f"[+] Caracteres recuperados del canal ICMP: {cifrado!r}\n")

    # Genera los 26 descifrados posibles y puntua cada uno.
    candidatos = [(k, descifrar_cesar(cifrado, k)) for k in range(26)]
    puntajes = {k: puntuar(t) for k, t in candidatos}
    mejor = max(puntajes, key=puntajes.get)

    print("Corrimiento | Texto descifrado")
    print("-" * 50)
    for k, texto in candidatos:
        linea = f"   k={k:2d}     | {texto}"
        if k == mejor:
            print(f"{VERDE}{linea}   <== MAS PROBABLE{RESET}")
        else:
            print(linea)

    print(f"\n[+] Corrimiento mas probable: k={mejor}")
    print(f"[+] Mensaje en claro recuperado: {descifrar_cesar(cifrado, mejor)!r}")


if __name__ == "__main__":
    main()
