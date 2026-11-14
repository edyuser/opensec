<div align="center">⬡ OpenSec

Python Cybersecurity & Security Utilities Library

Reconhecimento · Análise Web · Network Enumeration · File Encryption

Uma biblioteca Python de utilitários para reconhecimento de redes, análise de aplicações web e criptografia de arquivos.

<br>"Python" (https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
"Platform" (https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-555555?style=for-the-badge)
"Version" (https://img.shields.io/badge/Version-1.0-2563EB?style=for-the-badge)
"License" (https://img.shields.io/badge/License-Educational%20%26%20Authorized-16A34A?style=for-the-badge)

<br>Leve. Portável. Simples. Desenvolvida para segurança.

"Documentação" (#-documentação) · "Instalação" (#-instalação) · "Exemplos" (#-exemplos) · "Módulos" (#-módulos)

</div>---

Sobre o projeto

OpenSec é uma biblioteca Python desenvolvida para disponibilizar ferramentas de reconhecimento, análise técnica e segurança informática através de uma interface simples e programável.

O projeto reúne diferentes funcionalidades de cibersegurança numa única biblioteca, permitindo que estudantes, programadores e profissionais realizem tarefas de análise e reconhecimento sem depender de várias ferramentas independentes.

A biblioteca utiliza principalmente recursos da própria biblioteca padrão do Python, mantendo uma estrutura leve e compatível com diferentes ambientes.

Objetivos

- Simplificar tarefas comuns de reconhecimento e análise.
- Disponibilizar ferramentas reutilizáveis em projetos Python.
- Facilitar atividades de aprendizagem em cibersegurança.
- Reunir funcionalidades de rede, web e criptografia.
- Oferecer uma interface simples para integração em outros projetos.

---

Funcionalidades

Módulo| Funcionalidades
Net| Descoberta de hosts, identificação MAC, varredura de portas TCP e fingerprint de sistemas operacionais.
WebSec| Reconhecimento web, DNS, WHOIS, TLS, HTTP, extração de conteúdo e análise de formulários.
MelisaCry| Criptografia e descriptografia de arquivos e diretórios utilizando Fernet ou AES-256-GCM.

Destaques

- Reconhecimento de dispositivos numa rede local.
- Identificação de portas e serviços.
- Consulta de informações DNS e WHOIS.
- Análise de certificados TLS.
- Extração de HTML, JavaScript, CSS, links e imagens.
- Recolha de informações públicas de contacto.
- Testes básicos de reflexão XSS e análise de formulários.
- Criptografia de arquivos e diretórios inteiros.

---

Tecnologias

A OpenSec foi desenvolvida utilizando:

Tecnologia| Utilização
Python| Linguagem principal
Socket| Comunicação e reconhecimento de rede
SSL| Análise de certificados TLS
Urllib| Requisições HTTP
OS| Integração com o sistema operacional
Cryptography| Criptografia de arquivos (dependência opcional)

Dependência externa: "cryptography", necessária apenas para utilizar o módulo MelisaCry.

---

Instalação

Requisitos

- Python 3.8 ou superior.
- Linux ou Windows.
- pip.

Instalação através do código-fonte

Clone o repositório:

git clone https://github.com/edyuser/opensec.git

Entre na pasta:

cd opensec

Instale a biblioteca:

pip install .

Instalação através do Wheel

Também podes instalar diretamente através do pacote ".whl" disponibilizado nas Releases:

pip install ./dist/opensec-1.0.0-py3-none-any.whl

Substitua o nome pelo ficheiro efetivamente disponibilizado.

Dependência de criptografia

Para utilizar o módulo MelisaCry:

pip install cryptography

Importação

from OpenSec import Net
from OpenSec import WebSec
from OpenSec import MelisaCry

---

Módulos

01. Net — Network Enumeration

O módulo "Net" disponibiliza ferramentas para reconhecimento e análise de redes.

Funcionalidades

Método| Descrição
"Net.list_me()"| Descobre hosts ativos na rede local.
"Net.list_me_mac()"| Obtém associações entre IP e MAC.
"Net.ports()"| Realiza varredura de portas TCP.
"Net.list_SO()"| Tenta identificar o sistema operacional remoto.
"Net.ports_version()"| Analisa portas abertas e banners de serviços.
"Net.static_full()"| Configura parâmetros de rede estática.

Exemplos

Descoberta de dispositivos

from OpenSec import Net

hosts = Net.list_me()

for host in hosts:
    print(host)

Descoberta de IP e MAC

from OpenSec import Net

devices = Net.list_me_mac()

for ip, mac in devices.items():
    print(f"IP: {ip} | MAC: {mac}")

Varredura de portas

from OpenSec import Net

Net.ports("192.168.1.10")

Definindo uma faixa personalizada:

Net.ports(
    "192.168.1.10",
    port_range=(1, 9999)
)

Identificação do sistema operacional

from OpenSec import Net

result = Net.list_SO("192.168.1.10")

print(result)

Identificação de serviços e versões

from OpenSec import Net

services = Net.ports_version("192.168.1.10")

print(services)

«Nota: "Net.static_full()" modifica configurações de rede do sistema e exige privilégios administrativos.»

---

02. WebSec — Web Reconnaissance

O módulo "WebSec" reúne funcionalidades de reconhecimento e análise de aplicações web.

Funcionalidades

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

Informações gerais de um website

from OpenSec import WebSec
import json

info = WebSec.get_info("https://example.com")

print(
    json.dumps(
        info,
        indent=2,
        ensure_ascii=False,
        default=str
    )
)

DNS

from OpenSec import WebSec

print(WebSec.resolve("example.com"))

print(WebSec.reverse("8.8.8.8"))

WHOIS

from OpenSec import WebSec

result = WebSec.whois("example.com")

print(result)

TLS Analysis

from OpenSec import WebSec

tls = WebSec.tls_info("example.com")

print(tls)

Extração HTML

from OpenSec import WebSec

result = WebSec.get_html("https://example.com")

print(result["html"])
print(result["tamanho"])

Extração JavaScript

from OpenSec import WebSec

result = WebSec.get_js("https://example.com")

print(result["js_inline"])
print(result["js_externos"])

Extração CSS

from OpenSec import WebSec

result = WebSec.get_css("https://example.com")

print(result["css_inline"])
print(result["css_externos"])

Descoberta de links

from OpenSec import WebSec

links = WebSec.get_links("https://example.com")

print("Internos:")
print(links["links"]["internos"])

print("Externos:")
print(links["links"]["externos"])

Extração de imagens

from OpenSec import WebSec

images = WebSec.get_img("https://example.com")

print(images.urls())

images.save("./images/")

OSINT — Email Discovery

from OpenSec import WebSec
import json

result = WebSec.get_email("example.com")

print(
    json.dumps(
        result,
        indent=2,
        ensure_ascii=False
    )
)

Contact Information

from OpenSec import WebSec

contacts = WebSec.get_ctt(
    "https://example.com/contact"
)

print(contacts)

XSS Reflection Testing

from OpenSec import WebSec

result = WebSec.test_xss(
    "https://example.com/search?q="
)

print(result)

print(result.to_dict())

Também é possível utilizar payloads personalizados:

WebSec.test_xss(
    "https://example.com"
).js("""
<img src=x onerror=alert(1)>
""")

CSRF Inspection

from OpenSec import WebSec

result = WebSec.test_crf(
    "https://example.com/login"
)

print(result)
print(result.to_dict())

Importante: os resultados dos testes de reflexão não representam confirmação automática de vulnerabilidade. A validação deve ser feita manualmente.

---

03. MelisaCry — File Encryption

O módulo "MelisaCry" disponibiliza funcionalidades de criptografia simétrica para arquivos e diretórios.

Desenvolvido para simplificar operações de proteção de dados através de uma interface fluente.

Algoritmos disponíveis

Engine| Algoritmo
Fernet| AES-128-CBC + HMAC-SHA256
AES| AES-256-GCM

Seleção do algoritmo

from OpenSec import MelisaCry

MelisaCry.use("AES")

Ou:

MelisaCry.use("Fernet")

Geração de chave

from OpenSec import MelisaCry

key = MelisaCry.key("chave.txt")

print(key)

Se a chave não existir, uma nova será gerada e armazenada no caminho indicado.

Criptografia de arquivo

from OpenSec import MelisaCry

key = MelisaCry.key("chave.txt")

result = MelisaCry.crypt(
    "documento.txt"
).by_key(key)

print(result)

Criptografia de diretório

from OpenSec import MelisaCry

key = MelisaCry.key("chave.txt")

result = MelisaCry.crypt(
    "Documentos/"
).by_key(key)

print(result)

Descriptografia

from OpenSec import MelisaCry

key = MelisaCry.key("chave.txt")

result = MelisaCry.decrypt(
    "Documentos/"
).by_key(key)

print(result)

Interface fluente

Uma das características do MelisaCry é a utilização de uma interface simples:

MelisaCry.crypt("arquivo.txt").by_key(key)

MelisaCry.decrypt("arquivo.txt.melisa").by_key(key)

Retorno das operações

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

Os valores acima são ilustrativos.

«Aviso importante: a perda da chave pode tornar os dados permanentemente inacessíveis. Faça backups antes de utilizar o módulo e armazene as chaves em local seguro.»

---

Exemplo completo

A OpenSec permite combinar diferentes módulos num único script.

from OpenSec import Net
from OpenSec import WebSec
from OpenSec import MelisaCry

import json

# ==========================
# NETWORK ENUMERATION
# ==========================

hosts = Net.list_me()

print("Hosts encontrados:")
print(hosts)

# ==========================
# WEB RECONNAISSANCE
# ==========================

info = WebSec.get_info(
    "https://example.com"
)

print(json.dumps(
    info,
    indent=2,
    ensure_ascii=False,
    default=str
))

# ==========================
# LINK DISCOVERY
# ==========================

links = WebSec.get_links(
    "https://example.com"
)

print(links["links"]["internos"])

# ==========================
# FILE ENCRYPTION
# ==========================

MelisaCry.use("AES")

key = MelisaCry.key(
    "chave.txt"
)

result = MelisaCry.crypt(
    "relatorios/"
).by_key(key)

print(result)

---

Estrutura do projeto

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

Compatibilidade

Característica| Suporte
Python| 3.8+
Linux| Sim
Windows| Sim
Dependências externas| Apenas "cryptography" para MelisaCry
Interface| Python API
Distribuição| Wheel e Source Distribution

A disponibilidade de determinadas funcionalidades depende das permissões do sistema operacional e das ferramentas de sistema disponíveis.

---

Segurança e utilização responsável

A OpenSec foi desenvolvida para fins educacionais, investigação técnica e auditorias de segurança autorizadas.

A utilização das ferramentas de reconhecimento e testes deve respeitar a legislação aplicável e os direitos dos proprietários dos sistemas analisados.

Regras de utilização:

- Execute testes apenas em sistemas próprios ou com autorização formal.
- Não utilize as ferramentas para acesso não autorizado.
- Tenha cuidado ao modificar configurações de rede.
- Proteja as chaves utilizadas pelo MelisaCry.
- Faça backups antes de operações de criptografia.

O utilizador é responsável pela utilização das funcionalidades disponibilizadas pela biblioteca.

---

Distribuição

A OpenSec disponibiliza pacotes Python para instalação e distribuição.

Formatos disponíveis:

- ".whl" — Python Wheel.
- ".tar.gz" — Source Distribution.

Repositório oficial:

https://github.com/edyuser/opensec

---

<div align="center">OpenSec

Open-source Python Cybersecurity Library

Desenvolvida para estudantes, investigadores e profissionais de segurança informática.

<br>Version 1.0

Made with Python.

</div>
