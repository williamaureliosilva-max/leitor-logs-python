#!/usr/bin/env python3
"""
leitor_logs.py
Engine de parsing para análise estruturada de ficheiros Syslog e Apache.
Desenvolvido para a Unidade Curricular UC01482 - Cibersegurança.
"""

import re
import sys

# Padrão RegEx para RFC 5424 (Syslog): Captura Timestamp, Hostname, Serviço e Mensagem
PADRAO_SYSLOG = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)'
)

# Padrão RegEx para Apache Common Log Format: Captura IP, Timestamp, Método, URL e Status HTTP
PADRAO_APACHE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)'
)

def identificar_formato(linha):
    """Analisa a estrutura da linha para determinar o tipo de log."""
    if PADRAO_SYSLOG.match(linha):
        return "syslog"
    elif PADRAO_APACHE.match(linha):
        return "apache"
    else:
        return "desconhecido"

def parsear_syslog(linha):
    """Extrai metadados de uma linha formatada como Syslog."""
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
    """Extrai metadados de uma linha formatada como Apache Access Log."""
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
    """Realiza a leitura do ficheiro e processa as primeiras entradas para validação."""
    try:
        with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
            linhas = f.readlines()
    except FileNotFoundError:
        print(f"ERRO CRÍTICO: O ficheiro '{caminho}' não foi localizado no diretório.")
        sys.exit(1)

    print(f"Análise Iniciada. Total de registos encontrados: {len(linhas)}")
    print("-" * 60)

    # Processamento limitado às primeiras 5 entradas para demonstração de campos
    for i, linha in enumerate(linhas[:5]):
        linha = linha.strip()
        if not linha:
            continue

        formato = identificar_formato(linha)
        print(f"\nRegisto {i+1} [Protocolo: {formato.upper()}]:")
        print(f"  Raw Data: {linha[:80]}...")

        if formato == "syslog":
            campos = parsear_syslog(linha)
        elif formato == "apache":
            campos = parsear_apache(linha)
        else:
            campos = {}

        if campos:
            print("  Campos Estruturados:")
            for campo, valor in campos.items():
                print(f"    {campo}: {valor}")

    print("\n" + "=" * 60)
    print("Processamento e extração de metadados concluídos com sucesso.")

if __name__ == "__main__":
    # Interface de Linha de Comando (CLI)
    if len(sys.argv) < 2:
        print("Uso: python leitor_logs.py <ficheiro_de_log>")
        sys.exit(1)
    processar_ficheiro(sys.argv[1])
