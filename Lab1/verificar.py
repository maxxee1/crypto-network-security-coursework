"""Verificador de sigilo + SIMULADOR DPI.

Audita si tu trafico (salida.pcap) es indistinguible del 'ping' nativo del SO
de la maquina atacada. Tiene dos capas:

  1) SIMULADOR DPI (siempre corre): imita lo que haria un DPI real. NO se le
     dice el SO: clasifica cada Echo Request comparando su firma (TTL, tamano y
     patron deterministico) contra las firmas nativas de Windows/Linux/macOS.
     Veredicto: "es un ping <SO> legitimo" o "ALARMA: no calza con ningun ping
     nativo / patron alterado". Asi se valida, por ejemplo, que el trafico
     pase como macOS y sea IGUAL a un ping macOS real.

  2) AUDITORIA DETALLADA (si se da --os y/o --real): compara byte a byte contra
     el perfil del SO y/o contra un ping real capturado, clasificando cada
     diferencia como timestamp (OK), canal encubierto (OK) o patron (DELATA).

Uso:
  python3 verificar.py --stealth salida.pcap                 # solo simulador DPI
  python3 verificar.py --stealth salida.pcap --os macos      # DPI + auditoria vs perfil
  python3 verificar.py --stealth salida.pcap --real real.pcap --os macos
"""
import argparse

from scapy.all import rdpcap, IP, ICMP, Raw

import perfiles

VERDE = "\033[92m"
ROJO = "\033[91m"
AMAR = "\033[93m"
RESET = "\033[0m"


def echo_requests(paquetes):
    return [p for p in paquetes if ICMP in p and p[ICMP].type == 8 and Raw in p]


def primer_echo_request(paquetes, preferida=56):
    reqs = echo_requests(paquetes)
    if not reqs:
        return None
    por_tam = {}
    for p in reqs:
        por_tam.setdefault(len(bytes(p[Raw].load)), p)
    if len(por_tam) > 1:
        print(f"[i] Echo requests encontrados (tamanos de data): {sorted(por_tam)} bytes")
    if preferida in por_tam:
        return por_tam[preferida]
    menor = min(por_tam)
    print(f"[!] No hay payload de {preferida}B; uso el mas chico ({menor}B).")
    return por_tam[menor]


def ok(cond):
    return f"{VERDE}OK{RESET}" if cond else f"{ROJO}DETECTABLE{RESET}"


# ---------------------------------------------------------------------------
#  SIMULADOR DPI: clasifica el trafico contra las firmas nativas conocidas.
# ---------------------------------------------------------------------------
def calza_con_perfil(pkt, perfil):
    """True si el paquete es indistinguible del ping nativo de ese perfil.

    Compara TTL, tamano de data y el PATRON deterministico byte a byte,
    permitiendo diferencias solo en la zona de timestamp [0:ts_len] (donde va
    el byte encubierto). Es exactamente lo que compararia un DPI por firma."""
    data = bytes(pkt[Raw].load)
    ttl_ok = pkt[IP].ttl == perfil["ttl"]
    tam_ok = len(data) == perfil["ts_len"] + len(perfil["patron"])
    if not (ttl_ok and tam_ok):
        return False, ttl_ok, tam_ok, None
    off = perfil["patron_offset"]
    patron_ok = data[off:off + len(perfil["patron"])] == perfil["patron"]
    return (ttl_ok and tam_ok and patron_ok), ttl_ok, tam_ok, patron_ok


def simular_dpi(paquetes, sospechado=None):
    print("=" * 68)
    print(f" SIMULADOR DPI  (clasificacion por firma, sin conocer el SO)")
    print("=" * 68)
    reqs = echo_requests(paquetes)
    if not reqs:
        print(f"{ROJO}No hay Echo Requests que analizar.{RESET}")
        return
    # Usa el ping de usuario (tamano estandar), evitando sondas de sistema.
    por_tam = {}
    for p in reqs:
        por_tam.setdefault(len(bytes(p[Raw].load)), p)
    pkt = por_tam.get(56) or por_tam[min(por_tam)]

    coincidencias = []
    print(f"\n  {'SO':8s} {'TTL':>10s} {'Tamano':>10s} {'Patron':>10s}   Veredicto")
    print("  " + "-" * 60)
    for so, perfil in perfiles.PERFILES.items():
        calza, ttl_ok, tam_ok, patron_ok = calza_con_perfil(pkt, perfil)
        p_txt = "-" if patron_ok is None else ("OK" if patron_ok else "difiere")
        print(f"  {so:8s} {('OK' if ttl_ok else 'no'):>10s} "
              f"{('OK' if tam_ok else 'no'):>10s} {p_txt:>10s}   "
              f"{'CALZA' if calza else 'no calza'}")
        if calza:
            coincidencias.append(so)

    print("\n" + "-" * 68)
    if len(coincidencias) == 1:
        so = coincidencias[0]
        sig = perfiles.PERFILES[so]
        print(f"{VERDE} VEREDICTO DPI: el trafico es indistinguible de un ping {so.upper()} "
              f"legitimo.")
        print(f"                (TTL {sig['ttl']}, {sig['ts_len'] + len(sig['patron'])}B, "
              f"patron intacto). El DPI NO gatilla alarma.{RESET}")
        if sospechado and perfiles.normalizar(sospechado) != so:
            print(f"{AMAR}    Nota: esperabas {perfiles.normalizar(sospechado)}, "
                  f"pero calza como {so}.{RESET}")
        elif sospechado:
            print(f"{VERDE}    Confirmado: coincide con el SO indicado ({so}).{RESET}")
    elif len(coincidencias) > 1:
        print(f"{AMAR} VEREDICTO DPI: calza con varios perfiles {coincidencias} "
              f"(firmas ambiguas).{RESET}")
    else:
        print(f"{ROJO} VEREDICTO DPI: ALARMA. No calza con ningun ping nativo "
              f"(patron/TTL/tamano alterados).{RESET}")
    print("=" * 68 + "\n")
    return coincidencias


# ---------------------------------------------------------------------------
#  AUDITORIA DETALLADA (byte a byte vs perfil y/o ping real).
# ---------------------------------------------------------------------------
def auditar(stealth, ref_payload, ref_ttl, ts_len, covert_offset, patron, patron_offset,
            fuente, clasifica_patron=True):
    ds = bytes(stealth[Raw].load)
    print("=" * 68)
    print(f" AUDITORIA DETALLADA  (stealth vs {fuente})")
    print("=" * 68)

    print(f"\n{AMAR}[Campos de cabecera]{RESET}")
    checks = [
        ("Tamano del payload", len(ref_payload), len(ds), len(ref_payload) == len(ds)),
        ("IP TTL", ref_ttl, stealth[IP].ttl, ref_ttl == stealth[IP].ttl),
        ("ICMP type", 8, stealth[ICMP].type, stealth[ICMP].type == 8),
        ("ICMP code", 0, stealth[ICMP].code, stealth[ICMP].code == 0),
    ]
    for nombre, vr, vs, cond in checks:
        print(f"  {nombre:20s} ref={str(vr):>6s}  stealth={str(vs):>6s}  -> {ok(cond)}")

    print(f"\n{AMAR}[Zona de patron deterministico]{RESET}")
    detectables = 0
    if patron is not None:
        fin = patron_offset + len(patron)
        for i in range(patron_offset, min(fin, len(ds))):
            esperado = patron[i - patron_offset]
            if i == covert_offset:
                continue
            if ds[i] != esperado:
                detectables += 1
                print(f"  {ROJO}offset {i:2d}: esperado {esperado}, stealth {ds[i]}  (PATRON -> DELATA){RESET}")
        if detectables == 0:
            print(f"  patron intacto (offset {patron_offset}..{fin - 1}) -> {ok(True)}")
    else:
        detectables = None
        print("  (sin patron de referencia; use --os para chequear el patron)")

    print(f"\n{AMAR}[Diff byte a byte vs referencia]{RESET}")
    n = max(len(ref_payload), len(ds))
    diffs_patron = 0
    for i in range(n):
        br = ref_payload[i] if i < len(ref_payload) else None
        bs = ds[i] if i < len(ds) else None
        if br != bs:
            if i == covert_offset:
                zona = f"{VERDE}canal encubierto (OK){RESET}"
            elif not clasifica_patron:
                zona = f"{AMAR}difiere (timestamp? agrega --os para clasificar){RESET}"
            elif i < ts_len:
                zona = "timestamp (variable -> OK)"
            else:
                zona = f"{ROJO}PATRON (DELATA){RESET}"
                diffs_patron += 1
            print(f"  offset {i:2d}: ref={br} stealth={bs}  [{zona}]")

    print("\n" + "=" * 68)
    fallos_cabecera = sum(0 if c[3] else 1 for c in checks)
    total = fallos_cabecera + diffs_patron + (detectables or 0)
    if total == 0:
        print(f"{VERDE} VEREDICTO: indistinguible del ping nativo por comparacion de firma.")
        print(f"            Un DPI basado en patrones NO gatilla alarma.{RESET}")
    else:
        print(f"{ROJO} VEREDICTO: {total} diferencia(s) detectable(s). Ajusta el perfil o"
              f" usa --plantilla.{RESET}")
    print("=" * 68)


def main():
    p = argparse.ArgumentParser(description="Audita el sigilo de tu trafico ICMP (+ simulador DPI).")
    p.add_argument("--stealth", required=True, help="pcap generado por stealth.py")
    p.add_argument("--os", dest="so", help="SO a imitar: windows | linux | macos")
    p.add_argument("--real", help="pcap con un ping REAL de referencia (verdad de terreno)")
    args = p.parse_args()

    paquetes = rdpcap(args.stealth)

    # (1) Simulador DPI: siempre corre, no necesita --os ni --real.
    simular_dpi(paquetes, sospechado=args.so)

    # (2) Auditoria detallada: solo si se pide --os o --real.
    if not args.so and not args.real:
        return

    perfil = perfiles.PERFILES[perfiles.normalizar(args.so)] if args.so else None
    ts_len = perfil["ts_len"] if perfil else 0
    covert_offset = perfil["covert_offset"] if perfil else 0
    patron = perfil["patron"] if perfil else None
    patron_offset = perfil["patron_offset"] if perfil else 0
    preferida = (ts_len + len(patron)) if perfil else 56

    stealth = primer_echo_request(paquetes, preferida)
    if stealth is None:
        print(f"{ROJO}No encontre Echo Request en {args.stealth}{RESET}")
        return

    if args.real:
        real = primer_echo_request(rdpcap(args.real), preferida)
        if real is None:
            print(f"{ROJO}No encontre Echo Request en {args.real}{RESET}")
            return
        ref_payload = bytes(real[Raw].load)
        ref_ttl = real[IP].ttl
        fuente = "ping real"
    else:
        ref_payload = perfiles.payload_base(perfiles.normalizar(args.so))
        ref_ttl = perfil["ttl"]
        fuente = f"perfil {perfiles.normalizar(args.so)}"

    auditar(stealth, ref_payload, ref_ttl, ts_len, covert_offset, patron, patron_offset,
            fuente, clasifica_patron=bool(perfil))


if __name__ == "__main__":
    main()
