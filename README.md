# Multi-Format Log Parser & Security Event Analyzer

## 1. Descrição Técnica
Este projeto consiste num motor de processamento de logs desenvolvido em **Python**, utilizando **Expressões Regulares (RegEx)** para a extração automatizada de metadados. O sistema foi desenhado para identificar e separar componentes críticos de logs de infraestrutura, facilitando a auditoria e a monitorização de segurança.

### Funcionalidades:
*   **Detecção Automática:** Identifica se o input pertence ao padrão **RFC 5424 (Syslog)** ou **Apache Common Log Format**.
*   **Parsing Estruturado:** Transforma texto não estruturado em dicionários de dados.
*   **Tratamento de Erros:** Gestão de exceções para ficheiros não encontrados e erros de encoding.

---

## 2. Resultados da Execução

### Cenário A: Análise de Autenticação (Syslog)
**Ficheiro:** `auth.log`  
**Output Estruturado:**
*   **Linha 1:** [SYSLOG] | Host: servidor01 | Service: sshd | Event: Failed password
*   **Linha 4:** [SYSLOG] | Host: servidor01 | Service: sshd | Event: Accepted password

### Cenário B: Tráfego Web (Apache Access)
**Ficheiro:** `access.log`  
**Output Estruturado:**
*   **Linha 2:** [APACHE] | IP: 10.0.0.100 | Method: POST | Path: /login | Status: 401
*   **Linha 5:** [APACHE] | IP: 10.0.0.100 | Method: GET | Path: /naoexiste.html | Status: 404

---

## 3. Implementação
O script `leitor_logs.py` utiliza o módulo nativo `re` para compilar padrões de busca otimizados, garantindo alta performance mesmo em volumes de dados consideráveis.

*Desenvolvido no âmbito da Unidade Curricular UC01482 - Cibersegurança.*
