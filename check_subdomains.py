#!/usr/bin/env python3
"""
check_subdomains.py
--------------------
Verificador asíncrono y reanudable del estado de subdominios web.

Detecta:
  - Dominios "WILDCARD" (catch-all) leyendo solo los primeros N bytes de la
    respuesta, sin descargar el cuerpo completo -> ahorro de tiempo/ancho de banda.
  - Dominios "ACTIVO" con su cadena de redirecciones y URL final.
  - Dominios "INACTIVO" (timeout, conexión rechazada, error SSL, etc.).

Soporta reanudación: si el CSV de salida ya existe, los subdominios que
aparecen en él se omiten y solo se procesan los pendientes.
"""

import asyncio
import aiohttp
import csv
import os
import sys

# --- CONFIGURACIÓN ---
INPUT_FILE = "subdominios_unificados.txt"
OUTPUT_FILE = "resultados_curl.csv"
CATCHALL_KEYWORD = "Dominio no declarado"  # Palabra clave del wildcard (case-insensitive)
MAX_CONCURRENT = 100                       # Peticiones simultáneas (ajustar según ancho de banda)
TIMEOUT_SECONDS = 8                        # Tiempo máximo de espera por petición
SNIFF_BYTES = 2048                         # Bytes a leer para la detección temprana de wildcard
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) SubdomainChecker/1.0"

FIELDNAMES = ["subdominio", "protocolo", "status", "url_final", "estado", "error"]


async def read_snippet(response, n_bytes=SNIFF_BYTES):
    """
    Lee como máximo n_bytes del cuerpo de la respuesta SIN esperar a que
    termine de descargarse todo el contenido. Devuelve el texto decodificado
    (ignorando errores de encoding) y si la lectura se truncó.
    """
    raw = b""
    async for chunk in response.content.iter_chunked(1024):
        raw += chunk
        if len(raw) >= n_bytes:
            break
    return raw[:n_bytes].decode(errors="ignore")


async def check_domain(domain, session, semaphore, result_queue):
    """Evalúa un dominio primero por HTTPS, luego por HTTP si falla."""
    async with semaphore:
        last_error = "Error desconocido"

        for proto in ("https", "http"):
            url = f"{proto}://{domain}"
            try:
                async with session.get(
                    url,
                    allow_redirects=True,
                    ssl=False,  # Ignora certificados autofirmados/inválidos
                ) as response:

                    # 1. DETECCIÓN TEMPRANA DE WILDCARD (solo se leen SNIFF_BYTES)
                    snippet = await read_snippet(response)

                    if CATCHALL_KEYWORD.lower() in snippet.lower():
                        await result_queue.put({
                            "subdominio": domain,
                            "protocolo": proto,
                            "status": response.status,
                            "url_final": str(response.url),
                            "estado": "WILDCARD (Dominio no declarado)",
                            "error": "N/A",
                        })
                        return  # Salida inmediata: no se prueba el otro protocolo

                    # 2. DOMINIO VÁLIDO Y ACTIVO
                    redirect_chain = [str(r.url) for r in response.history]
                    redirect_info = " -> ".join(redirect_chain) if redirect_chain else "N/A"

                    await result_queue.put({
                        "subdominio": domain,
                        "protocolo": proto,
                        "status": response.status,
                        "url_final": str(response.url),
                        "estado": f"ACTIVO (Redirects: {redirect_info})",
                        "error": "N/A",
                    })
                    return  # Éxito: no se prueba el siguiente protocolo

            except asyncio.TimeoutError:
                last_error = "Timeout"
            except aiohttp.ClientConnectorError as e:
                last_error = f"Conexion rechazada: {str(e)[:60]}"
            except aiohttp.ClientSSLError as e:
                last_error = f"Error SSL: {str(e)[:60]}"
            except aiohttp.ClientOSError as e:
                last_error = f"Error de red: {str(e)[:60]}"
            except aiohttp.ClientPayloadError as e:
                last_error = f"Error de payload: {str(e)[:60]}"
            except aiohttp.ClientError as e:
                last_error = f"Error de cliente: {str(e)[:60]}"
            except Exception as e:
                last_error = str(e)[:60]

        # Si llegamos aquí, ambos protocolos (https y http) fallaron
        await result_queue.put({
            "subdominio": domain,
            "protocolo": "N/A",
            "status": "000",
            "url_final": "N/A",
            "estado": "INACTIVO / NO RESUELVE",
            "error": last_error,
        })


async def writer_worker(result_queue, total_domains):
    """Escribe los resultados en el CSV a medida que llegan y actualiza el progreso."""
    file_exists = os.path.isfile(OUTPUT_FILE)
    processed_count = 0

    # Abrimos en modo 'a' (append) para que sea reanudable
    with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)

        if not file_exists:
            writer.writeheader()
            f.flush()

        while True:
            result = await result_queue.get()
            if result is None:  # Señal de finalización
                result_queue.task_done()
                break

            writer.writerow(result)
            f.flush()
            os.fsync(f.fileno())  # Garantiza escritura real en disco (resistente a crash)

            processed_count += 1
            sys.stdout.write(
                f"\r[*] Progreso: {processed_count}/{total_domains} dominios evaluados..."
            )
            sys.stdout.flush()

            result_queue.task_done()


async def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Error: No se encuentra el archivo '{INPUT_FILE}'")
        sys.exit(1)

    # 1. LÓGICA DE REANUDACIÓN: Cargar dominios ya procesados
    processed_domains = set()
    if os.path.isfile(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("subdominio"):
                    processed_domains.add(row["subdominio"])
        print(f"[*] Modo reanudación activado. Se omitirán {len(processed_domains)} dominios ya evaluados.")

    # 2. Leer la lista de trabajo y filtrar los ya procesados
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        all_domains = [line.strip() for line in f if line.strip()]

    # Elimina duplicados conservando el orden
    seen = set()
    unique_domains = []
    for d in all_domains:
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)

    domains_to_process = [d for d in unique_domains if d not in processed_domains]
    total_to_process = len(domains_to_process)

    if total_to_process == 0:
        print("[+] ¡Todos los dominios de la lista ya han sido evaluados!")
        return

    print(f"[*] Iniciando escaneo asíncrono de {total_to_process} dominios pendientes...")
    print(f"[*] Concurrencia: {MAX_CONCURRENT} | Timeout: {TIMEOUT_SECONDS}s | Sniff: {SNIFF_BYTES} bytes")

    # 3. Configuración de colas, semáforo y sesión HTTP
    result_queue = asyncio.Queue()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    connector = aiohttp.TCPConnector(
        limit=MAX_CONCURRENT,
        limit_per_host=20,      # Evita saturar un mismo host con demasiadas conexiones
        ttl_dns_cache=300,
        force_close=False,
    )
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
    headers = {"User-Agent": USER_AGENT}

    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        writer_task = asyncio.create_task(writer_worker(result_queue, total_to_process))

        tasks = [
            asyncio.create_task(check_domain(domain, session, semaphore, result_queue))
            for domain in domains_to_process
        ]

        # Esperamos a que todas las evaluaciones terminen (sin abortar si alguna falla)
        await asyncio.gather(*tasks, return_exceptions=True)

        # Señal de parada al escritor y esperamos a que termine de escribir
        await result_queue.put(None)
        await writer_task

    print("\n[+] ¡Proceso completado con éxito!")
    print(f"[+] Resultados guardados en: {OUTPUT_FILE}")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(
            "\n\n[!] Interrupción detectada. El progreso se ha guardado. "
            "Puedes volver a ejecutar el script y continuará donde lo dejaste."
        )
        sys.exit(0)
