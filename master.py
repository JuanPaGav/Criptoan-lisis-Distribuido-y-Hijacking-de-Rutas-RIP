#!/usr/bin/env python3
# master.py - Coordinador del cluster y particionador de rangos.
# Lee el objetivo, parte el espacio, reparte por TCP, calcula, e imprime avance.

import hashlib, json, socket, threading, sys, time
from queue import Queue, Empty

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"   # base36 (a-z 0-9)
CHUNK   = 200_000
PORT    = 9000

# Envía un objeto JSON por la conexión TCP, terminado en una nueva línea.
def send(f, obj): f.write((json.dumps(obj) + "\n").encode()); f.flush()

# Lee una línea JSON de la conexión y la convierte en un objeto;
# devuelve None si la conexión terminó.
def recv(f):
    line = f.readline()
    return json.loads(line) if line else None

# Convierte un índice numérico en una clave posible.
def key_at(i, length):
    s = ""
    for _ in range(length):
        s = CHARSET[i % 36] + s
        i //= 36
    return s

# Prueba las claves del rango indicado y devuelve una que coincida con el digest, 
# si la encuentra.
def crack(prefix, target, length, a, b):
    for i in range(a, b):
        k = key_at(i, length)
        if hashlib.md5(prefix + k.encode().ljust(16, b"\x00")).digest() == target:
            return k
    return None

# Lee el archivo PCAP y extrae los bytes del mensaje RIP autenticado 
# que se usarán como objetivo.
def leer_pcap(path):                               # lector minimo, sin scapy
    data = open(path, "rb").read()
    i = data.find(bytes.fromhex("ffff0003"))       # marca RIPv2 + Keyed-MD5
    if i < 4:
        sys.exit("No encontre un paquete RIP-MD5 en ese pcap.")
    start = i - 4
    plen = int.from_bytes(data[start + 8:start + 10], "big")
    return data[start:start + plen + 20]           # plen + trailer(4) + digest(16)

# --- objetivo: payload en hex, o ruta .pcap ---
raw = input("Payload RIP en hex (o ruta .pcap): ").strip()
if raw.lower().endswith(".pcap"):
    payload = leer_pcap(raw)
else:
    try:
        payload = bytes.fromhex(raw)
    except ValueError:
        sys.exit("Eso no es hex ni un archivo .pcap.")

length    = int(input("Longitud de la passkey [6]: ") or 6)
n_workers = int(input("¿Cuantos trabajadores esperas? [3]: ") or 3)

off = int.from_bytes(payload[8:10], "big") + 4
prefix, target = payload[:off], payload[off:off + 16]
total = 36 ** length
print(f"digest={target.hex()}  espacio={total:,} candidatos")

# --- cola de fragmentos [a, b) sin solapamiento ---
work = Queue()
for a in range(0, total, CHUNK):
    work.put((a, min(a + CHUNK, total)))

found  = threading.Event()
answer = {}
progress = {"done": 0}                             # candidatos ya completados (colectivo)
plock = threading.Lock()

# Suma a la cuenta compartida el número de candidatos contabilizados como procesados.
def add_done(n):
    with plock:
        progress["done"] += n

# Obtiene el siguiente bloque de la cola, salvo que ya se haya encontrado una clave.
def next_chunk():
    if found.is_set(): return None
    try: return work.get_nowait()
    except Empty: return None

# Registra la clave encontrada y señala que debe detenerse la búsqueda.
def win(key, who):
    if not found.is_set():
        answer["key"] = key
        found.set()
        print(f"\n[+] CLAVE = '{key}'  (la encontro {who})")

# Hace que el propio maestro tome bloques de la cola y pruebe claves.
def local_worker():                                # el maestro tambien calcula
    while True:
        c = next_chunk()
        if c is None: return
        k = crack(prefix, target, length, *c)
        add_done(c[1] - c[0])
        if k: return win(k, "maestro")

# Atiende a un trabajador remoto: le envía la configuración y los bloques, recibe sus 
# resultados y devuelve a la cola un bloque si la conexión se cierra antes de responder.
def serve(conn, addr):                             # atiende a un trabajador remoto
    f = conn.makefile("rwb")
    send(f, {"prefix": prefix.hex(), "target": target.hex(), "length": length})
    while True:
        c = next_chunk()
        if c is None: break
        send(f, {"start": c[0], "end": c[1]})
        r = recv(f)
        if r is None:                              # el trabajador se cayo:
            work.put(c); break                     #   devuelvo su fragmento a la cola
        add_done(c[1] - c[0])
        if r.get("key"): win(r["key"], addr[0]); break
    send(f, {"stop": True})
    conn.close()

# Muestra periódicamente el avance y la velocidad aproximada del clúster.
def monitor():                                     # log de avance colectivo
    t0 = time.time()
    while not found.is_set():
        time.sleep(2)
        d = progress["done"]; el = time.time() - t0
        if d and not found.is_set():
            print(f"[maestro] {d:,}/{total:,} ({100*d/total:.1f}%) | "
                  f"{d/el/1e6:.2f} M HPS colectivo | {el:.0f}s")

# --- espera a los trabajadores y arranca todo ---
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", PORT)); srv.listen()
print(f"esperando {n_workers} trabajadores en el puerto {PORT} ...")
conns = [srv.accept() for _ in range(n_workers)]
for i, (c, a) in enumerate(conns, 1): print(f"  {i}/{n_workers} conectado {a[0]}")

threading.Thread(target=monitor, daemon=True).start()
threads = [threading.Thread(target=serve, args=(c, a)) for c, a in conns]
threads.append(threading.Thread(target=local_worker))
for t in threads: t.start()
for t in threads: t.join()

print("RESULTADO:", answer.get("key", "no encontrada"))
