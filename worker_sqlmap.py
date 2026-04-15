import redis
import subprocess
import json
import psycopg2 # Para conectar con tu Postgres

# --- CONFIGURACIÓN ---
REDIS_CONF = {'host': 'localhost', 'port': 6379, 'db': 0}
# Ajusta estos datos a tu Postgres local
DB_CONF = {
    'dbname': 'db_fuzzing', 
    'user': 'postgres',
    'password': 'password',
    'host': 'localhost'
}

r = redis.Redis(**REDIS_CONF)

def save_to_postgres(url, details):
    """Inserta el hallazgo en la tabla que ya tenés en n8n"""
    try:
        conn = psycopg2.connect(**DB_CONF)
        cur = conn.cursor()
        query = """
            INSERT INTO vulnerabilities (source, type, severity, url, description, solution, evidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cur.execute(query, (
            'SQLMap (Worker)', 
            'SQL Injection', 
            'critical', 
            url, 
            'Vulnerabilidad detectada mediante escaneo asíncrono profundo.',
            'Implementar consultas parametrizadas.',
            details[:500] # Guardamos los primeros 500 caracteres de la evidencia
        ))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ Error al guardar en Postgres: {e}")

print("🛡️ Worker de Seguridad UTN Activo. Esperando tareas de n8n...")

while True:
    # Bloquea hasta que n8n haga el 'Push' en la lista
    _, task_raw = r.blpop('sqlmap_tasks', 0)
    task = json.loads(task_raw)
    
    target_url = task.get('url')
    print(f"🚀 Iniciando SQLMap Level 5 en: {target_url}")
    
    # Comando usando tu ruta actual
    command = [
        "python", "C:\\Herramientas\\sqlmap\\sqlmap.py",
        "-u", target_url,
        "--batch", "--level", "3", "--risk", "1"
    ]
    
    result = subprocess.run(command, capture_output=True, text=True)
    
    if "is vulnerable" in result.stdout:
        print(f"🔥 ¡VULNERABILIDAD ENCONTRADA en {target_url}!")
        save_to_postgres(target_url, result.stdout)
    else:
        print(f"✅ Escaneo limpio para {target_url}")