import socket
import ssl
import time
import json
import urllib.request
import urllib.error
from datetime import datetime
import urllib.parse
class WebSec:


# OSINT: e-mails / contactos 

    _EMAIL_RE = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
    _PHONE_RE = r"(?:\+?[0-9][0-9\s\-.()]{7,}[0-9])"

    @staticmethod
    def get_email(url, timeout=10, whois=True, profundidade=0):
       
        import re
        import urllib.parse

        alvo = url if url.startswith(("http://", "https://")) else "https://" + url
        dominio = urllib.parse.urlparse(alvo).netloc.lower().removeprefix("www.")
        emails = set()
        fontes = []

        
        paginas = [alvo, urllib.parse.urljoin(alvo, "contato"),
                   urllib.parse.urljoin(alvo, "contact"),
                   urllib.parse.urljoin(alvo, "contacto"),
                   urllib.parse.urljoin(alvo, "about"),
                   urllib.parse.urljoin(alvo, "sobre")]
        if profundidade > 0:
            html0, _ = WebSec._fetch(alvo, timeout)
            if html0:
                for href in re.findall(r'href=["\']([^"\']+)["\']', html0, re.I):
                    texto = href.lower()
                    if any(p in texto for p in ("contato", "contact", "about", "sobre", "equipe", "team", "support", "suporte")):
                        paginas.append(urllib.parse.urljoin(alvo, href))

        for pagina in paginas[:8 + profundidade]:
            html, _ = WebSec._fetch(pagina, timeout)
            if not html:
                continue
            fonte = pagina
            for e in set(re.findall(WebSec._EMAIL_RE, html)):
                
                if not re.search(r"\.(png|jpe?g|gif|svg|webp|css|js)$", e, re.I):
                    emails.add(e.lower())
                    fontes.append({"email": e.lower(), "fonte": fonte})
           
            for e in re.findall(r"([\w.\-]+)\s*(?:\(|\[)?\s*at\s*(?:\)|\])?\s*([\w.\-]+)\s*(?:\(|\[)?\s*dot\s*(?:\)|\])?\s*(com|org|net|br|io|dev)", html, re.I):
                emails.add(f"{e[0]}@{e[1]}.{e[2]}".lower())
                fontes.append({"email": f"{e[0]}@{e[1]}.{e[2]}".lower(), "fonte": fonte + " (ofuscado)"})

        if whois:
            w = WebSec.whois(dominio)
            raw = w.get("_raw", "")
            for e in set(re.findall(WebSec._EMAIL_RE, raw)):
                emails.add(e.lower())
                fontes.append({"email": e.lower(), "fonte": f"whois:{dominio}"})

        return {"dominio": dominio, "emails": sorted(emails), "fontes": fontes, "total": len(emails)}

    @staticmethod
    def get_ctt(url, timeout=10):
    
        import re
        import urllib.parse

        html, base = WebSec._fetch(url, timeout)
        if html is None:
            return base

        texto = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.I | re.S)
        texto_plano = re.sub(r"<[^>]+>", " ", texto)

        telefones = sorted({p.strip() for p in re.findall(WebSec._PHONE_RE, texto_plano)
                            if len(re.sub(r"\D", "", p)) >= 8})
        emails = sorted({e.lower() for e in re.findall(WebSec._EMAIL_RE, texto_plano)
                         if not re.search(r"\.(png|jpe?g|gif|svg|webp)$", e, re.I)})

        # redes sociais
        sociais = {}
        for rede, padrao in {
            "facebook": r"(?:facebook\.com|fb\.com)/[\w.\-]+",
            "instagram": r"instagram\.com/[\w.\-]+",
            "twitter": r"(?:twitter\.com|x\.com)/[\w.]+",
            "linkedin": r"linkedin\.com/(?:in|company)/[\w.\-]+",
            "youtube": r"youtube\.com/[\w@.\-]+",
            "whatsapp": r"wa\.me/[\d]+",
            "telegram": r"t\.me/[\w.\-]+",
        }.items():
            achados = sorted({urllib.parse.urljoin(base.get("url_final", url), m)
                              for m in re.findall(padrao, html, re.I)})
            if achados:
                sociais[rede] = achados

        
        nomes = sorted(set(re.findall(r"(?:mailto:|tel:)[^\"'>]*[\"'>]\s*([A-ZÁ-Ú][\wÀ-ÿ]+ [A-ZÁ-Ú][\wÀ-ÿ]+)", html)))

        return {
            "url": base.get("url_final", url),
            "emails": emails,
            "telefones": telefones,
            "redes_sociais": sociais,
            "possiveis_nomes": nomes,
            "enderecos": [a.strip() for a in re.findall(
                r"(?:Rua|Av(?:enida)?|Avenida|Travessa|R\.)\s+[^,<\n]{5,80}", texto_plano, re.I)][:10],
        }

    #Testes: XSS / CSRF

    _XSS_PADROES = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "{{7*7}}", "${7*7}",  
    ]

    class XssResult:
     #   """Resultado de WebSec.test_xss(); encadeavel com .js(\"\"\"payload\"\"\")."""

        def __init__(self, resultado):
            self.resultado = resultado

        def __repr__(self):
            r = self.resultado
            return (f"<XssResult: {r.get('parametros_testados', 0)} params, "
                    f"{len(r.get('refletidos', []))} reflexões, "
                    f"{len(r.get('possiveis_xss', []))} possíveis XSS>")

        def js(self, payload):
           
            return WebSec.test_xss(self.resultado["url"], payloads=[payload])

        def to_dict(self):
            return self.resultado

    @staticmethod
    def _extrair_params(url, timeout=10):
     
        import re
        import urllib.parse

        params = {}  
        p = urllib.parse.urlparse(url)
        if p.query:
            for k, _ in urllib.parse.parse_qsl(p.query):
                params[k] = "query"

        html, _ = WebSec._fetch(url, timeout)
        if not html:
            return params, None

        for form in re.findall(r"<form\b[^>]*>.*?</form>", html, re.I | re.S):
            m_action = re.search(r"action=[\"']([^\"']*)[\"']", form, re.I)
            m_method = re.search(r"method=[\"'](\w+)[\"']", form, re.I)
            action = urllib.parse.urljoin(url, m_action.group(1)) if m_action else url
            metodo = (m_method.group(1).lower() if m_method else "get")
            campos = re.findall(r"<(?:input|textarea|select)\b[^>]*name=[\"']([^\"']+)[\"']", form, re.I)
            for c in campos:
                params.setdefault(c, "query" if metodo == "get" else "post")
        return params, html

    @staticmethod
    def test_xss(url, payloads=None, timeout=10):
       
        import urllib.parse

        if payloads is None:
            payloads = WebSec._XSS_PADROES

        params, _ = WebSec._extrair_params(url, timeout)
        if not params:
            params = {"q": "query"}  

        marca = "opns3c"  
        testados, refletidos, possiveis = [], [], []

        for nome, tipo in params.items():
            for carga in payloads:
                valor = carga.replace("alert(1)", f"alert('{marca}')")
                alvo_url = url
                data = None
                if tipo == "query":
                    sep = "&" if urllib.parse.urlparse(url).query else "?"
                    alvo_url = f"{url}{sep}{urllib.parse.urlencode({nome: valor})}"
                else:
                    data = urllib.parse.urlencode({nome: valor}).encode()

                req = urllib.request.Request(alvo_url, data=data, headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        corpo = resp.read(500000).decode(errors="replace")
                except Exception:
                    continue

                if valor in corpo:
                    refletidos.append({"param": nome, "tipo": tipo, "payload": carga})
                    
                    bruto = carga.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
                    if valor in corpo and bruto not in corpo:
                        
                        possiveis.append({"param": nome, "payload": carga,
                                          "nota": "refletido sem encoding HTML — verificar manualmente"})

            testados.append({"param": nome, "tipo": tipo})

        return WebSec.XssResult({
            "url": url,
            "parametros_testados": len(testados),
            "params": testados,
            "refletidos": refletidos,
            "possiveis_xss": possiveis,
            "payloads_padrao": payloads,
        })

    @staticmethod
    def test_crf(url, payloads=None, timeout=10):
        
        import re
        import urllib.parse

        html, base = WebSec._fetch(url, timeout)
        if html is None:
            return {"url": url, "erro": base.get("erro", "falha")}

        pagina = base.get("url_final", url)
        TOKEN_PADRAO = ("csrf", "token", "_token", "authenticity", "nonce", "xsrf")

        forms = []
        for f in re.findall(r"<form\b([^>]*)>(.*?)</form>", html, re.I | re.S):
            attrs, corpo = f
            m_action = re.search(r"action=[\"']([^\"']*)[\"']", attrs, re.I)
            m_method = re.search(r"method=[\"'](\w+)[\"']", attrs, re.I)
            action = urllib.parse.urljoin(pagina, m_action.group(1) or "")
            metodo = (m_method.group(1).lower() if m_method else "get")
            campos = re.findall(r"<(?:input|textarea|select)\b[^>]*name=[\"']([^\"']+)[\"']", corpo, re.I)
            tem_token = any(any(t in c.lower() for t in TOKEN_PADRAO) for c in campos)
            forms.append({"action": action, "metodo": metodo,
                          "campos": campos, "token_csrf": tem_token})

        if payloads is None:
            payloads = ["<style>opns3c</style>", "\"><script>alert('opns3c')</script>", "opns3c"]

        resultados = []
        for form in forms:
            for campo in form["campos"]:
                for carga in payloads:
                    data = None
                    alvo = form["action"] or pagina
                    if form["metodo"] == "get":
                        sep = "&" if urllib.parse.urlparse(alvo).query else "?"
                        alvo = f"{alvo}{sep}{urllib.parse.urlencode({campo: carga})}"
                    else:
                        data = urllib.parse.urlencode({campo: carga}).encode()
                    req = urllib.request.Request(alvo, data=data, headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
                    try:
                        with urllib.request.urlopen(req, timeout=timeout) as resp:
                            corpo_resp = resp.read(300000).decode(errors="replace")
                        aceito = carga in corpo_resp
                    except Exception:
                        aceito = False
                    resultados.append({"form_action": form["action"], "campo": campo,
                                       "payload": carga, "refletido": aceito})

        resultado = {
            "url": url,
            "formularios": forms,
            "formularios_sem_token": [f["action"] for f in forms if not f["token_csrf"]],
            "testes": resultados,
        }

        class _CrfResult:
            def __init__(self, r):
                self.resultado = r

            def __repr__(self):
                return (f"<CrfResult: {len(self.resultado['formularios'])} forms, "
                        f"{len(self.resultado['formularios_sem_token'])} sem token>")

            def js(self, payload):
                return WebSec.test_crf(self.resultado["url"], payloads=[payload])

            def to_dict(self):
                return self.resultado

        return _CrfResult(resultado)        

#Imagens

    class ImageSet:
       

        def __init__(self, imagens, meta):
            self.imagens = imagens      
            self.meta = meta           

        def __repr__(self):
            return f"<ImageSet: {len(self.imagens)} imagens de {self.meta.get('url_final', self.meta.get('url'))}>"

        def __iter__(self):
            return iter(self.imagens)

        def __len__(self):
            return len(self.imagens)

        def urls(self):
            #"""So as URLs sem metadados.
            return [i["url"] for i in self.imagens]

        def save(self, pasta=".", timeout=15):
            
            import os
            import urllib.parse
            import hashlib

            pasta = os.path.expanduser(pasta)
            os.makedirs(pasta, exist_ok=True)

            salvos, erros = {}, {}
            for img in self.imagens:
                url = img["url"]
               
                nome = os.path.basename(urllib.parse.urlparse(url).path)
                if not nome or "." not in nome:
                    nome = hashlib.md5(url.encode()).hexdigest()[:12] + ".img"
              
                base, ext = os.path.splitext(nome)
                caminho = os.path.join(pasta, nome)
                n = 1
                while nome in salvos.values():
                    nome = f"{base}_{n}{ext}"
                    caminho = os.path.join(pasta, nome)
                    n += 1

                try:
                    req = urllib.request.Request(url, headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                        "Referer": self.meta.get("url_final", ""),
                    })
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        dados = resp.read(20000000)  # limite 20 MB por imagem
                    with open(caminho, "wb") as f:
                        f.write(dados)
                    salvos[url] = caminho
                except Exception as e:
                    erros[url] = str(e)

            return {"salvos": salvos, "erros": erros, "pasta": pasta}

    @staticmethod
    def get_img(url, timeout=10):
        
        import re
        import urllib.parse

        html, base = WebSec._fetch(url, timeout)
        if html is None:
            base["imagens"] = []
            return WebSec.ImageSet([], base)

        pagina = base.get("url_final", url)
        imgs = []

        def add(caminho, tag, tipo="img"):
            if not caminho:
                return
            absoluto = urllib.parse.urljoin(pagina, caminho.strip())
            if absoluto.startswith(("http://", "https://")) and absoluto not in [i["url"] for i in imgs]:
                imgs.append({"url": absoluto, "tag": tag, "tipo": tipo})

        # <img src=...>
        for tag in re.findall(r"<img\b[^>]*>", html, re.IGNORECASE):
            m = re.search(r"src=[\"']([^\"']+)[\"']", tag, re.IGNORECASE)
            if m:
                add(m.group(1), tag)

        # <img srcset="a.jpg 1x, b.jpg 2x">
        for tag in re.findall(r"<img\b[^>]*>", html, re.IGNORECASE):
            m = re.search(r"srcset=[\"']([^\"']+)[\"']", tag, re.IGNORECASE)
            if m:
                for parte in m.group(1).split(","):
                    cand = parte.strip().split(" ")[0]
                    add(cand, tag, tipo="srcset")

        # CSS inline: url(...) dentro de <style> e style="..."
        for bloco in re.findall(r"<style[^>]*>(.*?)</style>", html, re.IGNORECASE | re.DOTALL):
            for u in re.findall(r"url\([\"']?([^)\"']+)[\"']?\)", bloco):
                add(u, "<style>", tipo="css")

        # <input type=image src=...>
        for u in re.findall(r"<input[^>]+type=[\"']image[\"'][^>]+src=[\"']([^\"']+)[\"']", html, re.IGNORECASE):
            add(u, "<input>", tipo="input")

        return WebSec.ImageSet(imgs, base)


#Conteudo / extracao

    @staticmethod
    def _fetch(url, timeout=10):
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read(2000000).decode(errors="replace")
                base = {
                    "url": url,
                    "url_final": resp.geturl(),
                    "status": resp.status,
                }
                return html, base
        except urllib.error.HTTPError as e:
            return None, {"url": url, "status": e.code, "erro_http": str(e.reason)}
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            return None, {"url": url, "erro": f"falha na conexão: {e}"}

    @staticmethod
    def get_html(url, timeout=10):
        
        html, base = WebSec._fetch(url, timeout)
        if html is None:
            base["html"] = None
            return base
        base["html"] = html
        base["tamanho"] = f"{len(html)} bytes"
        return base

    @staticmethod
    def get_js(url, timeout=10):
     
        import re
        html, base = WebSec._fetch(url, timeout)
        if html is None:
            base["js"] = None
            return base

        inline = [m.strip() for m in re.findall(r"<script[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL) if m.strip()]
        externos = []
        for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, re.IGNORECASE):
            externos.append(urllib.parse.urljoin(base.get("url_final", url), src))

        base.update({"js_inline": inline, "js_externos": externos})
        return base

    @staticmethod
    def get_css(url, timeout=10):
      
        import re
        html, base = WebSec._fetch(url, timeout)
        if html is None:
            base["css"] = None
            return base

        inline = [m.strip() for m in re.findall(r"<style[^>]*>(.*?)</style>", html, re.IGNORECASE | re.DOTALL) if m.strip()]
        externos = []
        for href in re.findall(r"<link[^>]+rel=[\"']stylesheet[\"'][^>]*href=[\"']([^\"']+)[\"']", html, re.IGNORECASE):
            externos.append(urllib.parse.urljoin(base.get("url_final", url), href))

        base.update({"css_inline": inline, "css_externos": externos})
        return base

    @staticmethod
    def get_links(url, timeout=10, internos=True, externos=True,unicos=True):
        
        import re
        import urllib.parse
        html, base = WebSec._fetch(url, timeout)
        if html is None:
            base["links"] = None
            return base

        pagina = base.get("url_final", url)
        dominio = urllib.parse.urlparse(pagina).netloc.lower().removeprefix("www.")

        todos = []
        for href in re.findall(r"<a[^>]+href=[\"']([^\"'#]+)[\"']", html, re.IGNORECASE):
            absoluto = urllib.parse.urljoin(pagina, href)
            alvo_dominio = urllib.parse.urlparse(absoluto).netloc.lower().removeprefix("www.")
            tipo = "interno" if dominio and (alvo_dominio == dominio or alvo_dominio == "") else "externo"
            todos.append({"url": absoluto, "tipo": tipo})

        if unicos:
            vistos, filtrados = set(), []
            for l in todos:
                if l["url"] not in vistos:
                    vistos.add(l["url"])
                    filtrados.append(l)
            todos = filtrados

        base["links"] = {
            "internos": [l["url"] for l in todos if l["tipo"] == "interno"] if internos else [],
            "externos": [l["url"] for l in todos if l["tipo"] == "externo"] if externos else [],
            "outros_recursos": {
                "forms": [urllib.parse.urljoin(pagina, a) for a in re.findall(r"<form[^>]+action=[\"']([^\"']+)[\"']", html, re.IGNORECASE)],
                "iframes": [urllib.parse.urljoin(pagina, a) for a in re.findall(r"<iframe[^>]+src=[\"']([^\"']+)[\"']", html, re.IGNORECASE)],
            },
        }
        return base





    #DNS / IP

    @staticmethod
    def resolve(domain):
      
        try:
            infos = socket.getaddrinfo(domain, None)
            ips = sorted({i[4][0] for i in infos})
            return ips
        except socket.gaierror:
            return []

    @staticmethod
    def reverse(ip):
    
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None

    #WHOIS

    @staticmethod
    def whois(domain):
       
        tld = domain.split(".")[-1]
        whois_servers = {
            "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
            "org": "whois.pir.org", "br": "whois.registro.br",
            "io": "whois.nic.io", "info": "whois.afilias.net",
            "xyz": "whois.nic.xyz", "dev": "whois.nic.google",
            "gov": "whois.nic.gov", "edu": "whois.educause.edu",
        }
        server = whois_servers.get(tld, f"whois.nic.{tld}")
        try:
            with socket.create_connection((server, 43), timeout=10) as s:
                s.sendall(f"{domain}\r\n".encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            text = data.decode(errors="replace")
        except (OSError, socket.timeout):
            return {"erro": f"falha ao consultar {server}"}

        info = {}
        for line in text.splitlines():
            if ":" in line and not line.startswith(("%", " ", "\t")):
                key, _, value = line.partition(":")
                key, value = key.strip().lower(), value.strip()
                if value and key:
                    info[key] = value
        info["_raw"] = text
        return info

    #HTTP

    @staticmethod
    def get_info(url, timeout=10):
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        host = url.split("//")[1].split("/")[0].split(":")[0]

        #DNS
        t0 = time.time()
        ips = WebSec.resolve(host)
        dns_time = time.time() - t0

        result = {
            "url": url,
            "host": host,
            "ips": ips,
            "ip_principal": ips[0] if ips else None,
            "dns_tempo": f"{dns_time*1000:.1f} ms",
            "reverse_dns": WebSec.reverse(ips[0]) if ips else None,
        }

        #HTTP request
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(200000).decode(errors="replace")
                result.update({
                    "status": resp.status,
                    "url_final": resp.geturl(),
                    "headers": dict(resp.headers),
                    "servidor": resp.headers.get("Server"),
                    "content_type": resp.headers.get("Content-Type"),
                    "resposta_tempo": f"{(time.time()-t0)*1000:.1f} ms",
                    "tamanho_pagina": f"{len(body)} bytes",
                })
                # redirecionou
                if resp.geturl() != url:
                    result["redirecionado"] = True
                else:
                    result["redirecionado"] = False
        except urllib.error.HTTPError as e:
            result.update({"status": e.code, "erro_http": str(e.reason)})
            return result
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            result["erro"] = f"falha na conexão: {e}"
            return result

        #titulo
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        result["titulo"] = m.group(1).strip() if m else None

        #TLS
        if url.startswith("https://"):
            result["tls"] = WebSec.tls_info(host)

        #whois 
        domain = ".".join(host.split(".")[-2:])  
        result["whois_resumo"] = WebSec._whois_resumo(domain)

        return result

    @staticmethod
    def tls_info(host, port=443):
        
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            dias = (not_after - datetime.utcnow()).days
            return {
                "emissor": dict(x[0] for x in cert["issuer"]).get("organizationName"),
                "sujeito": dict(x[0] for x in cert["subject"]).get("commonName"),
                "valido_ate": cert["notAfter"],
                "dias_restantes": dias,
            }
        except Exception as e:
            return {"erro": f"TLS: {e}"}

    @staticmethod
    def _whois_resumo(domain):
        w = WebSec.whois(domain)
        if "erro" in w:
            return w
        resumo = {}
        for key in ("registrar", "creationdate", "expirationdate", "updateddate",
                    "registrar abuse contact email", "nserver", "owner", "country"):
            for k, v in w.items():
                if key in k and k != "_raw":
                    resumo[k] = v if not isinstance(v, list) else v[:3]
        return resumo or {"nota": "nada extraído — ver _raw em WebSec.whois()"}

    

    @staticmethod
    def trace(url_or_ip, max_hops=15):
       
        target = url_or_ip.split("//")[-1].split("/")[0]
        try:
            dst_ip = socket.gethostbyname(target)
        except socket.gaierror:
            dst_ip = target

        hops = []
        for ttl in range(1, max_hops + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            try:
                s.sendto(b"", (dst_ip, 33434))
                try:
                    _, addr = s.recvfrom(1024)
                    hop = addr[0]
                except socket.timeout:
                    hop = None
            finally:
                s.close()
            hops.append({"hop": ttl, "ip": hop or "*"})
            if hop == dst_ip:
                break
        return hops
