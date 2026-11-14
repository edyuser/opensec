<div align="center">⬡ OpenSec

PYTHON CYBERSECURITY & SECURITY UTILITIES LIBRARY

Network Enumeration · Web Reconnaissance · File Encryption

<br>Uma biblioteca Python de utilitários para reconhecimento de redes, análise de aplicações web e criptografia de arquivos.

<br><img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-444444?style=for-the-badge&logo=linux&logoColor=white" alt="Platforms">
<img src="https://img.shields.io/badge/Version-1.0-2563EB?style=for-the-badge" alt="Version">
<img src="https://img.shields.io/badge/Category-Cybersecurity-0891B2?style=for-the-badge" alt="Cybersecurity"><br><br>

LIGHTWEIGHT. PORTABLE. BUILT FOR SECURITY.

<br>"INSTALAÇÃO" (#-instalação) · "FUNCIONALIDADES" (#-funcionalidades) · "DOCUMENTAÇÃO" (#-documentação) · "EXEMPLOS" (#-exemplos)

<br></div>---

01. Sobre a OpenSec

OpenSec é uma biblioteca Python de utilitários desenvolvida para facilitar tarefas de reconhecimento, análise técnica e segurança informática.

O projeto reúne diferentes ferramentas numa única interface programável, permitindo que estudantes, investigadores e profissionais de segurança realizem operações de análise de redes, reconhecimento web e proteção de arquivos.

A biblioteca utiliza principalmente a biblioteca padrão do Python, reduzindo dependências externas e facilitando a utilização em diferentes ambientes.

Filosofia do projeto

- Simplicidade na utilização.
- Portabilidade entre sistemas operacionais.
- Organização modular.
- Reutilização de código.
- Ferramentas acessíveis para aprendizagem e investigação.
- Desenvolvimento orientado para segurança informática.

---

02. Funcionalidades

A OpenSec está organizada em três módulos principais.

<div align="center">MODULE| DESCRIPTION
Net| Network Discovery & Enumeration
WebSec| Web Reconnaissance & Analysis
MelisaCry| File Encryption & Decryption

</div>Net — Network Enumeration

Ferramentas para reconhecimento e análise de redes:

- Descoberta de hosts ativos.
- Identificação de endereços MAC.
- Varredura de portas TCP.
- Identificação de sistemas operacionais.
- Detecção de serviços e versões.
- Configuração de rede estática.

WebSec — Web Reconnaissance

Ferramentas para reconhecimento e análise de aplicações web:

- DNS Lookup.
- Reverse DNS.
- WHOIS.
- TLS Certificate Analysis.
- HTTP Headers.
- HTML Extraction.
- JavaScript Extraction.
- CSS Extraction.
- Link Discovery.
- Image Collection.
- Email Discovery.
- Contact Information Extraction.
- Basic XSS Reflection Testing.
- CSRF Token Inspection.

MelisaCry — File Encryption

Ferramentas para proteção de arquivos e diretórios:

- Criptografia simétrica.
- Descriptografia.
- AES-256-GCM.
- Fernet.
- Geração e armazenamento de chaves.
- Processamento recursivo de diretórios.
- Relatórios de operações.

---

03. Tecnologias

Tecnologia| Utilização
Python| Linguagem principal
Socket| Comunicação e reconhecimento de rede
SSL| Análise de certificados TLS
Urllib| Requisições HTTP
OS| Integração com o sistema operacional
Cryptography| Criptografia de arquivos

Dependência opcional: "cryptography".

A dependência externa é necessária apenas para utilizar as funcionalidades do módulo MelisaCry.

---

04. Instalação

Requisitos

- Python 3.8 ou superior.
- pip.
- Linux ou Windows.

Método 1 — Instalação pelo código-fonte

Clone o repositório:

git clone https://github.com/edyuser/opensec.git

Entre no diretório:

cd opensec

Instale a biblioteca:

pip install .

Método 2 — Instalação pelo Wheel

A OpenSec também disponibiliza distribuição no formato Python Wheel.

pip install ./dist/opensec-1.0.0-py3-none-any.whl

Utilize o nome real do ficheiro disponibilizado na Release.

Dependência de criptografia

Para utilizar o módulo MelisaCry:

pip install cryptography

Importação

from OpenSec import Net
from OpenSec import WebSec
from OpenSec import MelisaCry

---

05. Documentação

MODULE 01 — Net

Network Discovery & Enumeration

O módulo Net disponibiliza ferramentas para reconhecimento e análise de redes locais e dispositivos.

Métodos disponíveis

Método| Descrição
"Net.list_me()"| Descobre hosts ativos na rede local.
"Net.list_me_mac()"| Obtém associações IP → MAC.
"Net.ports()"| Realiza varredura de portas TCP.
"Net.list_SO()"| Tenta identificar o sistema operacional.
"Net.ports_version()"| Identifica serviços e banners.
"Net.static_full()"| Configura parâmetros de rede estática.

01.1 — Network Discovery

Descoberta de hosts ativos:

from OpenSec import Net

hosts = Net.list_me()

for host in hosts:
    print(host)

01.2 — MAC Discovery

Identificação de endereços IP e MAC:

from OpenSec import Net

devices = Net.list_me_mac()

for ip, mac in devices.items():
    print(f"IP: {ip} | MAC: {mac}")

01.3 — Port Scanning

Varredura de portas TCP:

from OpenSec import Net

result = Net.ports("192.168.1.10")

print(result)

Faixa personalizada:

result = Net.ports(
    "192.168.1.10",
    port_range=(1, 9999)
)

print(result)

Também é possível analisar vários hosts:

hosts = Net.list_me()

result = Net.ports(hosts)

print(result)

01.4 — Operating System Fingerprinting

Tentativa de identificação do sistema operacional:

from OpenSec import Net

result = Net.list_SO("192.168.1.10")

print(result)

01.5 — Service Version Detection

Identificação de serviços e versões através de banners:

from OpenSec import Net

services = Net.ports_version(
    "192.168.1.10"
)

print(services)

01.6 — Static Network Configuration

Configuração estática de rede:

from OpenSec import Net

Net.static_full()

Atenção: esta operação altera configurações de rede e requer privilégios administrativos ou root.

---

MODULE 02 — WebSec

Web Reconnaissance & Analysis

O WebSec disponibiliza funcionalidades de reconhecimento e análise de aplicações web.

Métodos disponíveis

Método| Descrição
"get_info()"| Relatório geral de um website.
"tls_info()"| Informações de certificados TLS.
"resolve()"| Resolução DNS.
"reverse()"| Reverse DNS.
"whois()"| Consulta WHOIS.
"trace()"| Traceroute simplificado.
"get_html()"| Extração HTML.
"get_js()"| Extração JavaScript.
"get_css()"| Extração CSS.
"get_links()"| Descoberta de links.
"get_img()"| Recolha de imagens.
"get_email()"| Descoberta de emails.
"get_ctt()"| Extração de contactos.
"test_xss()"| Testes básicos de reflexão XSS.
"test_crf()"| Inspeção de formulários e CSRF.

02.1 — Website Information

Obtém informações gerais de um website:

from OpenSec import WebSec
import json

info = WebSec.get_info(
    "https://example.com"
)

print(json.dumps(
    info,
    indent=2,
    ensure_ascii=False,
    default=str
))

Informações incluídas:

- Endereços IP.
- Informações DNS.
- Tempos de resposta.
- HTTP Headers.
- Servidor.
- Certificado TLS.
- Informações WHOIS.
- Título da página.
- Redirecionamentos.

02.2 — DNS Lookup

from OpenSec import WebSec

ips = WebSec.resolve("example.com")

print(ips)

Reverse DNS:

hostname = WebSec.reverse("8.8.8.8")

print(hostname)

02.3 — WHOIS Lookup

from OpenSec import WebSec

result = WebSec.whois("example.com")

print(result)

02.4 — TLS Analysis

from OpenSec import WebSec

tls = WebSec.tls_info("example.com")

print(tls)

02.5 — HTML Extraction

from OpenSec import WebSec

result = WebSec.get_html(
    "https://example.com"
)

print(result["html"])
print(result["tamanho"])

02.6 — JavaScript Extraction

from OpenSec import WebSec

result = WebSec.get_js(
    "https://example.com"
)

print(result["js_inline"])
print(result["js_externos"])

02.7 — CSS Extraction

from OpenSec import WebSec

result = WebSec.get_css(
    "https://example.com"
)

print(result["css_inline"])
print(result["css_externos"])

02.8 — Link Discovery

Identificação de links internos e externos:

from OpenSec import WebSec

links = WebSec.get_links(
    "https://example.com"
)

print("Internal Links:")

print(links["links"]["internos"])

print("External Links:")

print(links["links"]["externos"])

02.9 — Image Collection

Recolha de imagens de uma página:

from OpenSec import WebSec

images = WebSec.get_img(
    "https://example.com"
)

print(images.urls())

images.save("./images/")

02.10 — Email Discovery

Descoberta de endereços de email publicamente disponíveis:

from OpenSec import WebSec
import json

result = WebSec.get_email(
    "example.com"
)

print(json.dumps(
    result,
    indent=2,
    ensure_ascii=False
))

02.11 — Contact Information

Extração de informações de contacto:

from OpenSec import WebSec

contacts = WebSec.get_ctt(
    "https://example.com/contact"
)

print(contacts)

02.12 — XSS Reflection Testing

Testes básicos de reflexão XSS:

from OpenSec import WebSec

result = WebSec.test_xss(
    "https://example.com/search?q="
)

print(result)

print(result.to_dict())

Payload personalizado:

result = WebSec.test_xss(
    "https://example.com"
).js("""
<img src=x onerror=alert(1)>
""")

print(result)

Os resultados identificam possíveis reflexões de payloads. Uma reflexão não significa necessariamente que exista uma vulnerabilidade explorável.

02.13 — CSRF Inspection

Inspeção de formulários e tokens anti-CSRF:

from OpenSec import WebSec

result = WebSec.test_crf(
    "https://example.com/login"
)

print(result)

print(result.to_dict())

Também permite testar payloads personalizados:

result = WebSec.test_crf(
    "https://example.com/login"
).js("""
<style>body{display:none}</style>
""")

print(result)

---

MODULE 03 — MelisaCry

File Encryption & Data Protection

MelisaCry é o módulo da OpenSec dedicado à criptografia e descriptografia de arquivos e diretórios.

Disponibiliza uma interface fluente para executar operações de proteção de dados.

Algoritmos disponíveis

Engine| Algoritmo| Característica
Fernet| AES-128-CBC + HMAC-SHA256| Criptografia autenticada.
AES| AES-256-GCM| Criptografia autenticada.

03.1 — Engine Selection

Selecionar Fernet:

from OpenSec import MelisaCry

MelisaCry.use("Fernet")

Selecionar AES:

MelisaCry.use("AES")

03.2 — Key Generation

Gerar ou carregar uma chave:

from OpenSec import MelisaCry

key = MelisaCry.key("chave.txt")

print(key)

Se o arquivo já existir, a chave será carregada. Caso contrário, uma nova chave será criada.

03.3 — File Encryption

Criptografar um arquivo:

from OpenSec import MelisaCry

key = MelisaCry.key("chave.txt")

result = MelisaCry.crypt(
    "documento.txt"
).by_key(key)

print(result)

03.4 — Directory Encryption

Criptografar um diretório inteiro:

from OpenSec import MelisaCry

key = MelisaCry.key("chave.txt")

result = MelisaCry.crypt(
    "Documentos/"
).by_key(key)

print(result)

O processamento é recursivo e pode abranger diferentes tipos de arquivos.

03.5 — File Decryption

Descriptografar arquivos:

from OpenSec import MelisaCry

key = MelisaCry.key("chave.txt")

result = MelisaCry.decrypt(
    "Documentos/"
).by_key(key)

print(result)

03.6 — Flexible Key Input

O método ".by_key()" aceita diferentes formatos:

# Objeto de chave
MelisaCry.crypt("arquivo.txt").by_key(key)

# String da chave
MelisaCry.crypt("arquivo.txt").by_key(key_string)

# Caminho do arquivo da chave
MelisaCry.crypt("arquivo.txt").by_key(
    "chave.txt"
)

03.7 — Operation Results

As operações retornam informações sobre o processamento:

{
    "engine": "AES",
    "operacao": "cifrar",
    "alvo": "Documentos/",
    "arquivos_ok": [],
    "erros": {},
    "pulados": [],
    "total": 0
}

Os valores apresentados são ilustrativos.

Proteção de dados

O MelisaCry possui alguns comportamentos importantes:

- Arquivos cifrados recebem a extensão ".melisa".
- Arquivos já cifrados são ignorados durante a cifragem.
- A chave não é cifrada pelo próprio processo.
- Apenas arquivos ".melisa" são processados durante a descriptografia.
- Erros individuais de descriptografia são reportados.
- A operação de cifragem remove o original após a cifragem bem-sucedida.

IMPORTANTE: a perda da chave pode tornar os dados permanentemente inacessíveis. Guarda a chave em local seguro e mantém backups dos arquivos originais antes de utilizar a biblioteca.

---

06. Exemplo completo

A OpenSec permite combinar os seus módulos num único programa Python.

from OpenSec import Net
from OpenSec import WebSec
from OpenSec import MelisaCry

import json


# =====================================
# NETWORK ENUMERATION
# =====================================

hosts = Net.list_me()

print("[NET] Active Hosts:")

for host in hosts:
    print(host)


# =====================================
# WEB RECONNAISSANCE
# =====================================

info = WebSec.get_info(
    "https://example.com"
)

print("\n[WEBSEC] Website Information:")

print(json.dumps(
    info,
    indent=2,
    ensure_ascii=False,
    default=str
))


# =====================================
# LINK DISCOVERY
# =====================================

links = WebSec.get_links(
    "https://example.com"
)

print("\n[WEBSEC] Internal Links:")

print(links["links"]["internos"])


# =====================================
# FILE ENCRYPTION
# =====================================

MelisaCry.use("AES")

key = MelisaCry.key(
    "chave.txt"
)

result = MelisaCry.crypt(
    "relatorios/"
).by_key(key)

print("\n[MELISACRY] Encryption Result:")

print(json.dumps(
    result,
    indent=2,
    ensure_ascii=False
))

---

07. Estrutura do projeto

OpenSec/
│
├── OpenSec/
│   ├── __init__.py
│   ├── net.py
│   ├── websec.py
│   └── melicry.py
│
├── dist/
│   ├── opensec-1.0.0-py3-none-any.whl
│   └── opensec-1.0.0.tar.gz
│
├── tests/
│
├── pyproject.toml
├── README.md
├── LICENSE
└── .gitignore

---

08. Compatibilidade

Característica| Suporte
Python| 3.8+
Linux| Sim
Windows| Sim
Dependências externas| "cryptography" opcional
Distribuição| Wheel / Source Distribution
Arquitetura| Modular

A disponibilidade de determinadas operações pode depender das permissões do sistema operacional e dos utilitários instalados.

---

09. Segurança e utilização responsável

A OpenSec foi desenvolvida para aprendizagem, investigação técnica e auditorias de segurança autorizadas.

A utilização das ferramentas deve respeitar a legislação aplicável e os direitos dos proprietários dos sistemas analisados.

Orientações:

- Execute testes apenas em sistemas próprios ou com autorização formal.
- Não utilize ferramentas de reconhecimento para acesso não autorizado.
- Tenha cuidado ao alterar configurações de rede.
- Proteja as chaves utilizadas pelo MelisaCry.
- Faça backups antes de operações de criptografia.
- Verifique manualmente os resultados dos testes de segurança.

O utilizador é responsável pela utilização das funcionalidades disponibilizadas pela biblioteca.

---

10. Distribuição

A OpenSec disponibiliza pacotes Python para distribuição.

Formato| Descrição
".whl"| Python Wheel — pacote de instalação.
".tar.gz"| Source Distribution — distribuição do código-fonte.

Os pacotes podem ser encontrados na secção Releases do repositório.

<br><div align="center">OPEN SOURCE PROJECT

OpenSec — Python Cybersecurity Library

Uma biblioteca. Diferentes ferramentas. Uma abordagem modular à segurança informática.

<br>""GitHub" (https://img.shields.io/badge/GitHub-edyuser%2Fopensec-181717?style=for-the-badge&logo=github)" (https://github.com/edyuser/opensec)

<br>Version 1.0

Developed with Python.

</div>
