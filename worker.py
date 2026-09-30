#!/usr/bin/env python3
# worker.py - Trabajador TCP que calcula resumenes MD5 (RFC 2082).
# Usa varios nucleos con multiprocessing e imprime avance (HPS y tiempo).

import hashlib, json, socket, os, time
from multiprocessing import Pool

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"   # base36 (a-z 0-9)

# Convierte un número de índice en una clave usando letras minúsculas y números.
def key_at(i, length):                             # numero -> texto en base 36
    s = ""
    for _ in range(length):
        s = CHARSET[i % 36] + s
        i //= 36
    return s

# Recorre un rango de índices y devuelve la clave cuyo resumen MD5 coincide 
# con el objetivo; si no encuentra una, devuelve None.
def crack(args):                                   # args = (prefix, target, length, a, b)
    prefix, target, length, a, b = args
    for i in range(a, b):
        k = key_at(i, length)
        if hashlib.md5(prefix + k.encode().ljust(16, b"\x00")).digest() == target:
            return k
    return None

# Envía un objeto como JSON por la conexión TCP, terminado en una nueva línea.
def send(f, obj): f.write((json.dumps(obj) + "\n").encode()); f.flush()

# Lee una línea JSON de la conexión y la convierte en un objeto; devuelve None 
# si la conexión terminó.
def recv(f):
    line = f.readline()
    return json.loads(line) if line else None

# Pide los datos de conexión, recibe la configuración y los rangos del maestro, 
# distribuye cada rango entre varios procesos y devuelve el resultado.
def main():
    host = input("IP del maestro [127.0.0.1]: ").strip() or "127.0.0.1"
    port = int(input("Puerto [9000]: ") or 9000)
    cores = os.cpu_count() or 1
    ncores = int(input(f"¿Cuantos nucleos usar? [{cores}]: ") or cores)

    conn = socket.create_connection((host, port))
    f = conn.makefile("rwb")
    cfg = recv(f)                                   # el maestro manda la config
    prefix = bytes.fromhex(cfg["prefix"])
    target = bytes.fromhex(cfg["target"])
    length = cfg["length"]
    print(f"conectado; usando {ncores} nucleos. calculando...")

    pool = Pool(ncores)
    done = 0
    t0 = time.time()
    last = t0
    while True:
        msg = recv(f)
        if msg is None or msg.get("stop"):
            break
        a, b = msg["start"], msg["end"]
        # parte el fragmento entre los nucleos y corre en paralelo
        step = (b - a + ncores - 1) // ncores
        tasks = [(prefix, target, length, s, min(s + step, b)) for s in range(a, b, step)]
        key = None
        for r in pool.imap_unordered(crack, tasks):
            if r:
                key = r
                break
        done += b - a
        now = time.time()
        if now - last >= 1:                         # log de avance ~cada segundo
            print(f"[worker] {done:,} probados, {done/(now-t0)/1e6:.2f} M de HPS, {now-t0:.0f}s")
            last = now
        send(f, {"key": key})                       # devuelve la clave o None
        if key:
            print(f"¡ENCONTRE: {key}!")
    pool.terminate()
    conn.close()

if __name__ == "__main__":
    main()