#!/usr/bin/env python3
"""
leitor_logs.py
Le um ficheiro de log e mostra as primeiras linhas com os campos separados.
UC01482 - Atividade 3-2
"""

import re
import sys

# Padrao para Syslog
PADRAO_SYSLOG = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)'
)

# Padrao para Apache Access Log
PADRAO_APACHE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)'
)

def identificar_formato(linha):
    if PADRAO_SYSLOG.match(linha):
        return "syslog"
    elif PADRAO_APACHE.match(linha):
        return "apache"
    else:
        return "desconhecido"

def parsear_syslog(linha):
    m = PADRAO_SYSLOG.match(linha)
    if m:
        return {
            "timestamp": m.group(1),
            "hostname": m.group(2),
            "programa": m.group(3),
            "mensagem": m.group(4)
        }
    return {}

def parsear_apache(linha):
    m = PADRAO_APACHE.match(linha)
    if m:
        return {
            "ip_cliente": m.group(1),
            "timestamp": m.group(2),
            "metodo": m.group(3),
            "url": m.group(4),
            "codigo_resposta": m.group(5)
        }
    return {}

def processar_ficheiro(caminho):
    try:
        with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
            linhas = f.readlines()
    except FileNotFoundError:
        print("ERRO: Ficheiro '" + caminho + "' nao encontrado.")
        sys.exit(1)

    print("Total de linhas no ficheiro: " + str(len(linhas)))
    print("-" * 60)

    for i, linha in enumerate(linhas[:5]):
        linha = linha.strip()
        if not linha:
            continue

        formato = identificar_formato(linha)
        print("\nLinha " + str(i+1) + " [" + formato.upper() + "]:")
        print("  Original: " + linha[:80])

        if formato == "syslog":
            campos = parsear_syslog(linha)
        elif formato == "apache":
            campos = parsear_apache(linha)
        else:
            campos = {}

        if campos:
            print("  Campos extraidos:")
            for campo, valor in campos.items():
                print("    " + campo + ": " + valor)

    print("\n" + "=" * 60)
    print("Processamento concluido.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python leitor_logs.py <nome_do_ficheiro>")
        print("Exemplo: python leitor_logs.py auth.log")
        sys.exit(1)
    processar_ficheiro(sys.argv[1])