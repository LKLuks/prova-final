import re
import csv
from datetime import datetime

# Tenta abrir o log real; se falhar, usa o simulado
try:
    with open("/var/log/auth.log", "r") as f:
        lines = f.readlines()
except FileNotFoundError:
    with open("auth_fake.log", "r") as f:
        lines = f.readlines()

eventos = []

for linha in lines:
    if "Failed password" in linha or "authentication failure" in linha:
        eventos.append(("Tentativa de login inválida", linha.strip()))
    elif "sudo" in linha:
        eventos.append(("Uso de sudo", linha.strip()))
    elif "CRON" in linha and "CMD" in linha:
        eventos.append(("Execução agendada", linha.strip()))

# Escreve o CSV mesmo que esteja vazio
with open("eventos_seguranca.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Tipo de Evento", "Descrição"])
    for evento in eventos:
        writer.writerow(evento)

print(f"[{datetime.now()}] Análise concluída: {len(eventos)} evento(s) detectado(s).")
