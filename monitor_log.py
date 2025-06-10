import re
import csv
import os
from datetime import datetime

# Caminho dos logs a serem monitorados
AUTH_LOG = "/var/log/auth.log"  # Linux
OUTPUT_CSV = "eventos_seguranca.csv"

# Expressões regulares para eventos relevantes
REGEX_EVENTOS = {
    "login_invalido": r"Failed password for (invalid user )?(\w+) from ([\d\.]+)",
    "execucao_suspeita": r"COMMAND=.*(netcat|nc|nmap|telnet|python3? .*shell).*"
}

def extrair_eventos(log_path):
    eventos = []
    if not os.path.exists(log_path):
        print(f"Arquivo de log não encontrado: {log_path}")
        return eventos

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as log_file:
        for linha in log_file:
            for tipo, padrao in REGEX_EVENTOS.items():
                match = re.search(padrao, linha)
                if match:
                    eventos.append({
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "tipo_evento": tipo,
                        "descricao": linha.strip()
                    })
    return eventos

def salvar_em_csv(eventos, caminho_csv):
    existe = os.path.exists(caminho_csv)
    with open(caminho_csv, 'a', newline='', encoding='utf-8') as csvfile:
        campos = ["timestamp", "tipo_evento", "descricao"]
        writer = csv.DictWriter(csvfile, fieldnames=campos)
        if not existe:
            writer.writeheader()
        for evento in eventos:
            writer.writerow(evento)

if __name__ == "__main__":
    print("🛡️  Monitorando logs de segurança...")
    eventos_detectados = extrair_eventos(AUTH_LOG)
    if eventos_detectados:
        salvar_em_csv(eventos_detectados, OUTPUT_CSV)
        print(f"✅ {len(eventos_detectados)} evento(s) salvo(s) em {OUTPUT_CSV}")
    else:
        print("ℹ️  Nenhum evento de segurança encontrado.")

