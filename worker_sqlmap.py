import redis
import subprocess
import json
import psycopg2 
import re 
import logging

# --- CONFIGURACIÓN DE LOGS ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("sqlmap-worker")

# --- CONFIGURACIÓN ---
REDIS_CONF = {'host': 'localhost', 'port': 6379, 'db': 0}
DB_CONF = {
    'dbname': 'fuzzing_db', 
    'user': 'postgres',
    'password': 'tutuca05',
    'host': 'localhost'
}

r = redis.Redis(**REDIS_CONF)

def extract_payload(stdout_text):
    title_match = re.search(r'Title:\s*(.+)', stdout_text)
    payload_match = re.search(r'Payload:\s*(.+)', stdout_text)
    
    if title_match and payload_match:
        return title_match.group(1).strip(), payload_match.group(1).strip()
    return None, None

def save_to_postgres(url, title, payload, scan_id):
    try:
        logger.info(f"💾 Intentando guardar hallazgo en BD para {url}...")
        conn = psycopg2.connect(**DB_CONF)
        cur = conn.cursor()
        query = """
            INSERT INTO vulnerabilities (scan_id, source, type, severity, url, description, solution, evidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        evidence = f"Técnica: {title}\nPayload: {payload}"
        
        cur.execute(query, (
            scan_id,
            'SQLMap (Worker)', 
            'SQL Injection', 
            'critical', 
            url, 
            'Vulnerabilidad detectada mediante escaneo asíncrono profundo.',
            'Implementar consultas parametrizadas.',
            evidence 
        ))
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"✅ Hallazgo guardado exitosamente en BD para el scan_id={scan_id}")
    except Exception as e:
        logger.error(f"❌ Error al guardar en Postgres: {e}")

logger.info("🛡️ Worker de Seguridad Activo. Esperando tareas...")

while True:
    _, task_raw = r.blpop('sqlmap_test', 0)
    
    try:
        task = json.loads(task_raw)
    except json.JSONDecodeError:
        logger.warning(f"⚠️ Basura o mensaje inválido ignorado en Redis: {task_raw}")
        continue 

    # Agregamos un log para ver exactamente qué JSON está llegando
    logger.info(f"📥 Nueva tarea recibida: {task}")
    
    # ¡CORRECCIÓN CRÍTICA AQUÍ! Agregamos 'urlsFound' que es lo que manda n8n
    targets_url = task.get('urlsFound') or task.get('urls') or task.get('url') or []
    current_scan_id = task.get('scan_id', 'Desconocido')
    
    if isinstance(targets_url, str):
        targets_url = [targets_url]

    logger.info(f"🔍 URLs a procesar encontradas: {len(targets_url)}")

    for target_url in targets_url:
        if not target_url:
            continue
            
        logger.info(f"🚀 Iniciando SQLMap en: {target_url}")
        
        level = task.get('level', 5)
        risk = task.get('risk', 3)

        # Comando adaptado: Sin flush-session
        command = [
            "python", "C:\\Herramientas\\sqlmap\\sqlmap.py",
            "-u", target_url,
            "--cookie", "PHPSESSID=746c64jq78gg8944qeom28ldr6; security=low",
            "--batch",
            "--random-agent",
            f"--level={level}", 
            f"--risk={risk}"
        ]
        
        logger.info(f"⚙️ Comando a ejecutar: {' '.join(command)}")
        
        try:
            logger.info("⏳ Ejecutando Subprocess de SQLMap... (esto puede tardar varios minutos)")
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            logger.info("✅ Subprocess de SQLMap finalizado.")

            print("🔍 Analizando resultados de SQLMap...")
            
            stdout_lower = result.stdout.lower()
            logger.info(f"📊 Código de salida: {stdout_lower}")
            
            if "parameter:" in stdout_lower and "is vulnerable" in stdout_lower:
                logger.info(f"🔥 ¡VULNERABILIDAD ENCONTRADA en {target_url}!")
                
                try:
                    with open("C:\\Herramientas\\reporte_vulnerabilidad.txt", "w", encoding="utf-8") as f:
                        f.write(result.stdout)
                except Exception as e:
                    logger.error(f"⚠️ No se pudo guardar el txt: {e}")

                title, payload = extract_payload(result.stdout)
                
                if title and payload:
                    save_to_postgres(target_url, title, payload, current_scan_id)
                else:
                    logger.warning("⚠️ No se pudo extraer el payload exacto para la base de datos.")
                    
            else:
                logger.info(f"✅ Escaneo limpio para {target_url}. No se encontraron vulnerabilidades.")
                
        except subprocess.TimeoutExpired:
            logger.error(f"⏳ Timeout al escanear {target_url}. La tarea alcanzó los 5 minutos y fue cancelada.")
