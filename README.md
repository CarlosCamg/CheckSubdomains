# Subdomain Checker

Script en Python 3 para verificar de forma **rápida, asíncrona y reanudable** el estado de una lista de subdominios web. Pensado para tareas de reconocimiento en pentesting / auditorías de infraestructura, con detección temprana de dominios *wildcard* (catch-all) para no perder tiempo procesándolos como si fueran hosts reales.

## Características

- ⚡ **Asíncrono**: usa `asyncio` + `aiohttp` para lanzar cientos de peticiones concurrentes (configurable).
- 🎯 **Detección temprana de wildcard**: lee solo los primeros 2 KB de cada respuesta; si contiene la palabra clave del catch-all, descarta el dominio y pasa al siguiente sin descargar el resto del cuerpo.
- 🔁 **Fallback de protocolo**: prueba `https://` primero y cae a `http://` si falla.
- 🌐 **Sigue redirecciones** y reporta la URL final y la cadena completa de redirects.
- 🛡️ **Tolerante a fallos**: ignora errores de certificado SSL, controla timeouts y captura excepciones de red sin detener el escaneo completo.
- 💾 **Reanudable**: si se interrumpe (`Ctrl+C`, caída del sistema, etc.), al volver a ejecutarlo continúa donde se quedó, sin repetir dominios ya evaluados.
- 📊 **Progreso en tiempo real** en consola.
- 📄 **Salida en CSV**, lista para filtrar con `grep`/`awk`.

## Requisitos

- Python 3.8+
- [aiohttp](https://docs.aiohttp.org/)

### Instalación

```bash
pip install aiohttp
```

## Uso

1. Crea un archivo de texto con un subdominio por línea, por ejemplo `subdominios_unificados.txt`:

   ```
   app.ejemplo.com
   api.ejemplo.com
   dev.ejemplo.com
   ```

2. Ejecuta el script:

   ```bash
   python3 check_subdomains.py
   ```

3. Los resultados se guardan progresivamente en `resultados_curl.csv`. Puedes cortar la ejecución en cualquier momento con `Ctrl+C` y relanzarla más tarde: los subdominios ya evaluados se omiten automáticamente.

## Configuración

Todas las opciones están al inicio de `check_subdomains.py`:

| Variable            | Descripción                                              | Valor por defecto                |
|---------------------|-----------------------------------------------------------|-----------------------------------|
| `INPUT_FILE`        | Archivo con la lista de subdominios (uno por línea)       | `subdominios_unificados.txt`     |
| `OUTPUT_FILE`        | Archivo CSV de salida                                     | `resultados_curl.csv`            |
| `CATCHALL_KEYWORD`  | Cadena que identifica una respuesta wildcard (case-insensitive) | `Dominio no declarado`      |
| `MAX_CONCURRENT`    | Peticiones concurrentes                                    | `100`                             |
| `TIMEOUT_SECONDS`   | Timeout por petición (segundos)                            | `8`                                |
| `SNIFF_BYTES`       | Bytes leídos para la detección temprana de wildcard         | `2048`                             |
| `USER_AGENT`        | User-Agent enviado en las peticiones                        | Navegador genérico Linux          |

## Formato de salida (`resultados_curl.csv`)

| Columna       | Descripción                                                        |
|---------------|---------------------------------------------------------------------|
| `subdominio`  | Subdominio evaluado                                                  |
| `protocolo`   | `https`, `http` o `N/A` si ambos fallaron                            |
| `status`      | Código HTTP de la respuesta final (o `000` si no hubo respuesta)     |
| `url_final`   | URL final tras seguir redirecciones                                  |
| `estado`      | `ACTIVO (Redirects: ...)`, `WILDCARD (Dominio no declarado)` o `INACTIVO / NO RESUELVE` |
| `error`       | Detalle del error de red, si lo hubo                                 |

### Filtrar resultados con bash

```bash
# Solo dominios activos
grep "ACTIVO" resultados_curl.csv
    
# Solo wildcards (ruido, catch-all)
grep "WILDCARD" resultados_curl.csv

# Solo inactivos
grep "INACTIVO" resultados_curl.csv

# Activos con código 200 exacto
awk -F',' '$3=="200"' resultados_curl.csv

# Resumen por estado
awk -F',' 'NR>1{print $5}' resultados_curl.csv | sed 's/ (.*//' | sort | uniq -c
```

## Notas

- `ssl=False` ignora certificados autofirmados o inválidos; es intencional para entornos de auditoría interna, pero ten esto en cuenta si el script se usa fuera de ese contexto.
- Ajusta `MAX_CONCURRENT` y `TIMEOUT_SECONDS` según el ancho de banda disponible y la tolerancia del objetivo a picos de tráfico.
- Pensado para uso en entornos donde tienes autorización explícita para escanear los dominios/IPs objetivo.
            
