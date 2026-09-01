# Informe Laboratorio 1 — Sección 1

**Alumno:** (tu nombre)
**e-mail:** maximiliano.solorza@mail.udp.cl
**Agosto de 2026**

---

## 1. Descripción

Se audita un sistema de Deep Packet Inspection (DPI) que dice detectar filtraciones
de información. La tarea es construir software que **replique el tráfico de `ping`
con su configuración por defecto**, pero transportando información confidencial en
el campo *data* de los paquetes ICMP, de manera que **no gatille alarmas** al
compararse contra tráfico real. Como prueba de concepto se demuestra que, conociendo
el algoritmo, recuperar el mensaje en claro es trivial (MitM + fuerza bruta sobre el
César).

Archivos entregados:

| Actividad | Archivo | Qué hace |
|-----------|---------|----------|
| 1 | `cesar.py` | Cifra texto con el algoritmo César (string + corrimiento). |
| 2 | `stealth.py` | Envía el texto cifrado, 1 carácter por paquete ICMP tipo *ping*. |
| 3 | `mitm.py` | Captura los paquetes, reconstruye el cifrado y rompe el César. |

---

## 2. Idea de la evasión (por qué no gatilla alarmas)

El payload por defecto de un `ping` de **Linux** mide **56 bytes**:

```
[ 0 : 8 ]  timestamp   -> CAMBIA en cada paquete (campo no determinístico)
[ 8 : 56]  patrón      -> 0x08 0x09 0x0a ... 0x37  (SIEMPRE idéntico)
```

- El carácter secreto se esconde en el **primer byte del timestamp**. Como ese campo
  varía legítimamente entre un ping y otro, un DPI que compara el payload contra un
  ping real **no puede distinguirlo**: no existe un valor "correcto" de timestamp.
- Los 48 bytes de patrón (`0x08..0x37`) se dejan **intactos**, que es la parte
  determinística que un DPI compararía. Al ser idéntica → no hay alarma.
- El `id` ICMP se mantiene constante (una "sesión" de ping) y el `seq` se incrementa
  1, 2, 3… igual que el ping real. El intervalo de envío es de 1 s (default de ping).
- **Fin de mensaje:** el último paquete lleva el carácter `b` como sentinela
  (según el enunciado: *"El último carácter del mensaje se transmite como una b"*).
  El receptor deja de leer al ver la `b`.

---

## 3. Cómo ejecutar

```bash
# Actividad 1 — cifrar
python3 cesar.py "Mensaje secreto" 3

# Actividad 2 — generar tráfico stealth a un pcap (sin root, para Wireshark)
python3 stealth.py "Mensaje secreto" 3 --pcap salida.pcap
#   Enviar de verdad por la red:
sudo python3 stealth.py "Mensaje secreto" 3 --enviar --destino 8.8.8.8

# Actividad 3 — MitM: leer el pcap y romper el cifrado
python3 mitm.py --pcap salida.pcap
#   O capturar en vivo:
sudo python3 mitm.py --sniff --iface en0
```

> Requiere `pip3 install scapy`. Para `--enviar` y `--sniff` se necesitan privilegios
> (raw sockets). Para la demostración basta con el flujo `--pcap` + Wireshark.

---

## 4. Desarrollo de Actividades

### 3.1 Actividad 1 — Algoritmo de cifrado

**Prompt entregado a ChatGPT:**

> "Genera un programa en python3 que cifre texto con el algoritmo César. El programa
> debe recibir como parámetros por línea de comandos el string a cifrar y luego el
> corrimiento (entero). Solo debe desplazar letras a-z y A-Z, dejando intactos
> espacios, números y signos."

**Validación:** el código cumple. Recibe `texto` y `corrimiento` como argumentos,
desplaza únicamente las letras usando aritmética módulo 26 y respeta mayúsculas /
minúsculas. Ejemplo:

```
$ python3 cesar.py "Mensaje secreto" 3
Texto cifrado: Phqvdmh vhfuhwr
```

*(Pega aquí el screenshot de la ejecución.)*

### 3.2 Actividad 2 — Modo stealth

**Prompt entregado a ChatGPT:**

> "Genera un programa en python3 con scapy que envíe un string carácter por carácter
> dentro de paquetes ICMP Echo Request (uno por paquete, en el campo data), imitando
> exactamente a un ping por defecto de Linux (56 bytes de data: 8 de timestamp + el
> patrón 0x08..0x37), de modo que un DPI no lo distinga de un ping real. El carácter
> secreto debe ir escondido en el timestamp para no alterar el patrón. Debe poder
> guardar los paquetes en un .pcap y también enviarlos por la red, mostrar los campos
> de un ping real antes y después, y marcar el fin de mensaje con el carácter 'b'."

**Validación:** el código cumple. Construye los 56 bytes idénticos a un ping de Linux,
inserta el carácter en `data[0]` (dentro del timestamp), mantiene el patrón
`0x08..0x37` intacto, incrementa `seq`, imprime los campos de un ping real previo y
posterior, verifica que el patrón coincide con el ping real y cierra con la sentinela
`b`. Ejemplo de salida (recortada):

```
[+] Mensaje cifrado  : Phqvdmh vhfuhwr
[+] Se transmite     : 'Phqvdmh vhfuhwrb'  (ultimo = sentinela 'b')

=== PING REAL (previo) ===
  ICMP type       : 8 (Echo Request)
  data[8:56] patron: 08 09 0a 0b ... 37

=== NUESTRO PAQUETE (caracter 'P') ===
  data[0:8]  ts   : 50 <..timestamp..>      <- 0x50 = 'P' escondido
  data[8:56] patron: 08 09 0a 0b ... 37      <- IDENTICO al ping real

[+] Patron 0x08..0x37 identico al ping real: True  -> DPI no gatilla alarma
```

*(Pega aquí el screenshot de la ejecución y una captura de Wireshark comparando un
ping real con uno de `salida.pcap`: mismo tamaño, mismo patrón, mismos campos.)*

### 3.3 Actividad 3 — MitM

**Prompt entregado a ChatGPT:**

> "Genera un programa en python3 con scapy que lea un archivo pcap (o capture ICMP en
> vivo), extraiga de cada Echo Request el primer byte del data hasta encontrar la
> sentinela 'b', reconstruya el texto cifrado, y como no se conoce el corrimiento del
> César pruebe los 26 posibles y los imprima todos, resaltando en verde la opción más
> probable de ser el mensaje en claro (usando frecuencia de letras y palabras comunes
> del español)."

**Validación:** el código cumple. Recupera los caracteres, arma el cifrado, genera los
26 descifrados y puntúa cada uno con un diccionario de palabras frecuentes + la
frecuencia de letras del español; imprime todo y marca en verde el mejor. Ejemplo:

```
[+] Caracteres recuperados del canal ICMP: 'Phqvdmh vhfuhwr'

Corrimiento | Texto descifrado
--------------------------------------------------
   k= 0     | Phqvdmh vhfuhwr
   ...
   k= 3     | Mensaje secreto   <== MAS PROBABLE   (en verde)
   ...
```

Esto demuestra la prueba de concepto: **conociendo el algoritmo (César + canal ICMP),
recuperar el mensaje es inmediato** aunque no se conozca el corrimiento.

*(Pega aquí el screenshot con la línea verde.)*

---

## 5. Cuatro *issues* al trabajar con ChatGPT

1. **Payload del ping incorrecto.** En las primeras respuestas ChatGPT usaba un data
   arbitrario (o la cadena `abcdef...` de Windows) en vez del patrón real de Linux
   `0x08..0x37`. Un DPI lo habría detectado de inmediato; hubo que corregirlo
   explicando el formato exacto de 56 bytes.

2. **Dónde esconder el carácter.** Inicialmente proponía reemplazar un byte del
   patrón, lo que rompe la comparación con el ping real y gatilla alarma. Hubo que
   indicarle que el dato debía ir en el **timestamp** (campo variable) para no ser
   detectable.

3. **Permisos / raw sockets.** El código sugerido asumía que `send`/`sniff` funcionan
   sin más, sin advertir que requieren `sudo`. En macOS además el patrón por defecto
   difiere del de Linux, algo que ChatGPT no consideró y tuvo que aclararse.

4. **Ruptura del César poco robusta.** La primera versión del MitM elegía "la más
   probable" solo por frecuencia de la letra 'e', fallando con mensajes cortos. Hubo
   que pedirle una heurística mejor combinando frecuencia de letras **y** palabras
   comunes del español.

---

## 6. Conclusiones y comentarios

- Un canal encubierto sobre ICMP es viable y **difícil de detectar por comparación de
  patrones**, porque basta con imitar la parte determinística del ping y ocultar los
  datos en los campos que legítimamente varían (timestamp). Un DPI basado solo en
  *matching* de payload no gatilla alarmas.
- La detección real requeriría análisis de comportamiento (volumen/periodicidad de
  pings, entropía del timestamp, correlación con hosts internos), no solo comparación
  byte a byte.
- El César no aporta seguridad: solo 26 claves, roto por fuerza bruta al instante. La
  "protección" del esquema es la **ocultación** (esteganografía de red), no el cifrado;
  y la ocultación cae apenas se conoce el algoritmo, como muestra la Actividad 3.
- ChatGPT acelera el desarrollo pero requiere conocimiento del dominio para corregir
  supuestos incorrectos (formato exacto del ping, campo donde ocultar, permisos).
