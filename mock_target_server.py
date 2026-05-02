import time
import logging
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# --- CONFIGURACIÓN DEL SERVIDOR TRAMPA ---
TARGET_API_KEY = "REDACTED_API_KEY"
RATE_LIMIT_SECONDS = 1.0  # Máximo 1 petición por segundo por IP
MAX_STRIKES = 3  # A las 3 peticiones muy rápidas o prohibidas, se banea la IP temporalmente

# --- MEMORIA DEL WAF (Web Application Firewall) ---
ip_records = {}
banned_ips = set()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [WAF] - %(message)s')

def check_waf(client_ip, path):
    now = time.time()
    
    # 1. Comprobar si está baneada
    if client_ip in banned_ips:
        logging.warning(f"BLOCKED: {client_ip} intentó acceder a {path} (IP Baneada)")
        abort(403, description="IP Banned by WAF.")

    # Inicializar registro
    if client_ip not in ip_records:
        ip_records[client_ip] = {"last_request": 0, "strikes": 0}

    record = ip_records[client_ip]

    # 2. Rate Limiting (Protección contra Fuzzing Rápido como ffuf sin delay)
    time_since_last = now - record["last_request"]
    record["last_request"] = now

    if time_since_last < RATE_LIMIT_SECONDS:
        record["strikes"] += 1
        logging.warning(f"RATE LIMIT: {client_ip} va muy rápido. Strike {record['strikes']}/{MAX_STRIKES}")
        if record["strikes"] >= MAX_STRIKES:
            banned_ips.add(client_ip)
            logging.error(f"BANNED: {client_ip} ha sido baneada por exceder la tasa de peticiones.")
            abort(403, description="Banned for rate limiting.")
        abort(429, description="Too Many Requests.")
    else:
        # Si va lento, reducimos los strikes lentamente
        record["strikes"] = max(0, record["strikes"] - 0.5)

    # 3. Honeypots (Rutas Trampa)
    honeypots = ["/admin", "/.env", "/config", "/wp-admin", "/server-status"]
    if any(path.startswith(hp) for hp in honeypots):
        record["strikes"] += 2
        logging.warning(f"HONEYPOT: {client_ip} tocó una ruta prohibida ({path}). Strikes suben a {record['strikes']}")
        if record["strikes"] >= MAX_STRIKES:
            banned_ips.add(client_ip)
            logging.error(f"BANNED: {client_ip} atrapado en Honeypot.")
        abort(403, description="Access Denied.")


@app.before_request
def waf_middleware():
    client_ip = request.remote_addr
    path = request.path
    check_waf(client_ip, path)

# --- RUTAS DE SIMULACIÓN ---

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])
def catch_all(path):
    """
    Simula la respuesta por defecto de la infraestructura.
    La mayoría de las rutas devuelven 404 Not Found de forma segura.
    """
    logging.info(f"REQUEST: {request.remote_addr} -> /{path} ({request.method})")
    
    # 4. RUTA VULNERABLE A SSRF (Nuevo Desafío)
    # Ejemplo: /v1/diagnostics?url=http://example.com
    if path == "v1/diagnostics":
        target_url = request.args.get("url")
        if not target_url:
            return jsonify({"error": "Missing 'url' parameter for diagnostic test."}), 400
            
        logging.info(f"DIAGNOSTIC: Attempting to fetch {target_url} on behalf of {request.remote_addr}")
        
        try:
            # ¡VULNERABILIDAD INTENCIONAL!
            # El servidor hace la petición a donde el usuario le diga, sin sanitizar.
            # Incluso permite esquemas 'file://' u otros locales usando librerías base.
            import urllib.request
            with urllib.request.urlopen(target_url) as response:
                content = response.read().decode('utf-8')
                return jsonify({
                    "status": "success", 
                    "diagnostic_target": target_url, 
                    "content_preview": content[:500] # Devolvemos los primeros 500 caracteres
                }), 200
        except Exception as e:
            return jsonify({"error": "Failed to reach target", "details": str(e)}), 500

    # RUTA SECRETA OBJETIVO (Ataque Anterior)
    if path == "v1/projectx" or path == "projectx":
        # Simulamos que existe, pero requiere autenticación
        api_key = request.headers.get("x-api-key")
        
        if not api_key:
            logging.info(f"MISSING AUTH: {request.remote_addr} intentó acceder a /{path} sin clave.")
            return jsonify({"error": "authentication required", "type": "auth_error"}), 401
            
        if api_key != TARGET_API_KEY:
            logging.info(f"INVALID KEY: {request.remote_addr} usó clave incorrecta '{api_key}' en /{path}.")
            return jsonify({"error": "invalid api key", "type": "auth_error"}), 403
            
        # ÉXITO: El atacante superó las defensas y encontró la clave
        logging.critical(f"BREACH: {request.remote_addr} ACCEDIÓ EXITOSAMENTE A LA RUTA CRÍTICA CON LA CLAVE CORRECTA.")
        return jsonify({
            "status": "success",
            "model": "projectx-v1",
            "capabilities": ["reasoning", "cybersecurity_auditing", "exploit_generation"],
            "message": "Bienvenido al entorno de desarrollo restringido de projectx."
        }), 200

    # Respuesta genérica para rutas no encontradas
    return jsonify({"error": "not_found_error"}), 404


if __name__ == '__main__':
    print("="*50)
    print("--- MOCK targetmodel SERVER INICIADO ---")
    print("Objetivo: Encontrar y acceder a la ruta oculta.")
    print("Reglas del WAF: Máximo 1 petición por segundo.")
    print("="*50)
    # Ejecutamos en localhost puerto 8080
    app.run(host='127.0.0.1', port=8080, debug=False)
