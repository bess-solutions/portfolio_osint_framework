# Framework Automatizado de OSINT y Threat Intelligence en la Nube

Un marco de trabajo pasivo y totalmente automatizado de Inteligencia de Amenazas (Threat Intelligence) y OSINT diseñado para funcionar 24/7 en la nube.

## Características Principales
- **Descubrimiento Pasivo de Subdominios:** Integración con `crt.sh` para rastrear certificados SSL y descubrir endpoints de desarrollo ocultos.
- **Threat Intelligence Automatizado:** Cruzamiento de activos descubiertos con APIs de VirusTotal, AlienVault OTX y URLScan.io.
- **Análisis Histórico:** Consultas a la API de Wayback Machine para identificar exposiciones de IP heredadas.
- **Entorno Local de Simulación:** Incluye un servidor de pruebas con reglas de WAF (Rate Limiting, Honeypots) y vulnerabilidades SSRF para práctica ofensiva (Red Teaming) segura y legal.
- **Consola Avanzada de Interacción API:** Cliente terminal en Python con soporte para enrutamiento SOCKS5 (Tor), inyección experimental de cabeceras y manipulación de payloads JSON para APIs altamente restringidas.

## Arquitectura
El sistema está diseñado para operar autónomamente en una máquina virtual de Google Cloud Platform (GCP) mediante `systemd`. Utiliza SQLite para la correlación de datos y genera reportes diarios de hipótesis de ataque sin establecer nunca una conexión directa contra la infraestructura objetivo.

## Configuración Local
1. Clona el repositorio.
2. Instala las dependencias: `pip install -r requirements.txt`
3. Configura tus claves de API (VirusTotal, SecurityTrails) en el archivo `config.yaml`.
4. Levanta el servidor local para pruebas: `python mock_target_server.py`
5. Prueba la consola ofensiva: `python api_interaction_console.py --use-mock --model ProjectX --key REDACTED_API_KEY`

*Nota: Este proyecto fue construido exclusivamente con fines defensivos, de monitoreo y educación en Red Teaming. Toda la información identificable, IPs y credenciales reales han sido ofuscadas.*
