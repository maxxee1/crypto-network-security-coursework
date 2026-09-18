"""Perfiles de 'ping' por sistema operativo.

Un DPI detecta trafico anomalo comparandolo contra el ping NATIVO del SO que
dice ser el origen. Por eso, para pasar desapercibido, hay que imitar la firma
exacta (TTL + payload) del SO de la maquina atacada.

Este modulo centraliza esos perfiles para que stealth.py (generador) y
verificar.py (auditor) usen SIEMPRE los mismos valores.

Firmas (lo que se ve en Wireshark):
  Windows : data 32 bytes = "abcdefghijklmnopqrstuvwabcdefghi", TTL 128, sin timestamp.
  Linux   : data 56 bytes = [8B timestamp][0x08 0x09 ... 0x37],   TTL 64.
  macOS   : data 56 bytes = [16B timestamp][0x10 0x11 ... 0x37],  TTL 64.

Nota de sigilo:
  En Linux/macOS el caracter secreto se esconde DENTRO del timestamp (campo que
  varia legitimamente entre pings) -> indetectable por comparacion de patron.
  En Windows NO hay timestamp: los 32 bytes son fijos, asi que ocultar un
  caracter altera un byte deterministico y es intrinsecamente mas detectable.
"""
import struct
import time


def timestamp(n_bytes):
    """Devuelve n_bytes de timestamp realista (segundos + microsegundos != 0)."""
    ahora = time.time()
    seg = int(ahora)
    usec = int((ahora - seg) * 1_000_000) or 1
    if n_bytes == 8:
        return bytearray(struct.pack("<II", seg, usec))      # 2 x 32 bits
    if n_bytes == 16:
        return bytearray(struct.pack("<qq", seg, usec))      # 2 x 64 bits
    if n_bytes == 0:
        return bytearray()
    return bytearray(struct.pack("<II", seg, usec))[:n_bytes]


PERFILES = {
    "windows": {
        "ttl": 128,
        "ts_len": 0,
        "patron_offset": 0,
        "patron": b"abcdefghijklmnopqrstuvwabcdefghi",   # 32 bytes fijos
        "covert_offset": 0,          # sobre-escribe la 'a' inicial
        "sigilo_real": False,        # sin timestamp -> ocultar es detectable
        "nota": "Payload 100% deterministico: ocultar datos ES detectable por un DPI estricto.",
    },
    "linux": {
        "ttl": 64,
        "ts_len": 8,
        "patron_offset": 8,
        "patron": bytes(range(0x08, 0x08 + 48)),          # 0x08..0x37 (48 bytes)
        "covert_offset": 0,          # dentro del timestamp (variable) -> sigiloso
        "sigilo_real": True,
        "nota": "Caracter oculto en el timestamp; patron 0x08..0x37 intacto.",
    },
    "macos": {
        "ttl": 64,
        "ts_len": 16,
        "patron_offset": 16,
        "patron": bytes(range(0x10, 0x10 + 40)),          # 0x10..0x37 (40 bytes)
        "covert_offset": 0,          # dentro del timestamp (variable) -> sigiloso
        "sigilo_real": True,
        "nota": "Caracter oculto en el timestamp; patron 0x10..0x37 intacto.",
    },
}

ALIAS = {"win": "windows", "mac": "macos", "osx": "macos", "linux": "linux"}


def normalizar(nombre):
    n = nombre.strip().lower()
    n = ALIAS.get(n, n)
    if n not in PERFILES:
        raise ValueError(f"SO desconocido: {nombre!r}. Use windows | linux | macos")
    return n


def payload_base(so):
    """Payload IDENTICO a un ping real del SO indicado (con timestamp fresco)."""
    p = PERFILES[so]
    return bytes(timestamp(p["ts_len"])) + p["patron"]
