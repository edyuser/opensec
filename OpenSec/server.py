import socket
import os
import io
import time
import threading
import zipfile

def _fmt(bps):
    for u in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024:
            return f"{bps:.1f} {u}"
        bps /= 1024
    return f"{bps:.1f} TB/s"


class Server:
    """
    Servidor TCP multi-cliente.
    Protocolo: 'TEXT|tamanho|nome\n' + payload.
    SOMENTE a thread _client_loop le do socket de cada cliente
    header + payload completos e enfileira; receive() so entrega da fila.
    """
    _sock = None
    _clients = {}          # ip -> socket
    _blocked = set()
    _lock = threading.Lock()
    _log_file = "conexoes.txt"
    _running = False
    _inbox = []            # itens completos ja baixados aguardando receive()

    #ciclo de vida

    @classmethod
    def start_on(cls, host="0.0.0.0", port=8000):
        if cls._running:
            print("[!] Servidor já está ativo.")
            return
        cls._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls._sock.bind((host, port))
        cls._sock.listen(10)
        cls._running = True
        threading.Thread(target=cls._accept_loop, daemon=True).start()
        print(f"[*] Servidor ativo em {host}:{port} — log: {cls._log_file}")

    @classmethod
    def stop(cls):
        cls._running = False
        with cls._lock:
            for s in list(cls._clients.values()):
                try: s.close()
                except OSError: pass
            cls._clients.clear()
        if cls._sock:
            try: cls._sock.close()
            except OSError: pass
        print("[*] Servidor parado.")

    #conexoes

    @classmethod
    def conections(cls):
       # """Lista de clientes conectados: [(ip, porta), ...]."""
        with cls._lock:
            return [(s.getpeername()[0], s.getpeername()[1])
                    for s in cls._clients.values()]

    @classmethod
    def block_ip(cls, ip):
        cls._blocked.add(ip)
        with cls._lock:
            s = cls._clients.pop(ip, None)
            if s:
                try: s.close()
                except OSError: pass
        print(f"[*] IP {ip} bloqueado.")

    @classmethod
    def unblock_ip(cls, ip):
        cls._blocked.discard(ip)
        print(f"[*] IP {ip} desbloqueado.")

    #thread que aceita conexoes

    @classmethod
    def _accept_loop(cls):
        while cls._running:
            try:
                client, addr = cls._sock.accept()
            except OSError:
                break
            ip, port = addr
            if ip in cls._blocked:
                client.close()
                print(f"[x] Conexão recusada (IP bloqueado): {ip}")
                continue
            with cls._lock:
                old = cls._clients.get(ip)
                if old:
                    try: old.close()
                    except OSError: pass
                cls._clients[ip] = client
            try:
                with open(cls._log_file, "a") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} CONECTOU {ip}:{port}\n")
            except OSError:
                pass
            print(f"[+] Nova conexão: {ip}:{port}")
            threading.Thread(target=cls._client_loop, args=(client, ip),
                             daemon=True).start()

    @classmethod
    def _client_loop(cls, client, ip):
        
        try:
            while True:
                #header
                header = b""
                while not header.endswith(b"\n"):
                    c = client.recv(1)
                    if not c:
                        raise ConnectionError
                    header += c
                op, size, name = header.decode().strip().split("|", 2)
                size = int(size)

                #aprova e baixa o payload
                client.sendall(b"OK\n")
                data, t0 = b"", time.time()
                while len(data) < size:
                    chunk = client.recv(min(65536, size - len(data)))
                    if not chunk:
                        raise ConnectionError
                    data += chunk
                    el = max(time.time() - t0, 0.001)
                    print(f"\r[↓] {ip} {len(data)/1048576:.2f}/{size/1048576:.2f} MB  "
                          f"{_fmt(len(data)/el)}   ", end="", flush=True)
                el = max(time.time() - t0, 0.001)
                print(f"\r[↓] {ip} {op} '{name}' {size/1048576:.2f} MB recebidos  "
                      f"{_fmt(size/el)}          ")

                with cls._lock:
                    cls._inbox.append({"op": op, "name": name,
                                       "data": data, "ip": ip})
        except (ConnectionError, OSError):
            pass
        finally:
            with cls._lock:
                cls._clients.pop(ip, None)
            print(f"[-] Desconectou: {ip}")

    #envio

    @classmethod
    def _targets(cls):
        with cls._lock:
            return list(cls._clients.values())

    @classmethod
    def _send_item(cls, op, name, data):
        targets = cls._targets()
        if not targets:
            print("[!] Nenhum cliente conectado.")
            return False
        header = f"{op}|{len(data)}|{name}\n".encode()
        for s in targets:
            try:
                s.sendall(header)
                resp = s.recv(4)
                if b"OK" not in resp:
                    print("[!] Cliente recusou o item.")
                    continue
                t0, sent = time.time(), 0
                total = len(data)
                for i in range(0, total, 65536):
                    s.sendall(data[i:i+65536])
                    sent += len(data[i:i+65536])
                    el = max(time.time() - t0, 0.001)
                    print(f"\r[↑] {sent/1048576:.2f}/{total/1048576:.2f} MB  "
                          f"{_fmt(sent/el)}   ", end="", flush=True)
                el = max(time.time() - t0, 0.001)
                print(f"\r[↑] {total/1048576:.2f} MB enviados  {_fmt(total/el)}          ")
            except OSError as e:
                print(f"[!] falha no envio: {e}")
        return True

    @classmethod
    def send_text(cls, text):
        cls._send_item("TEXT", "mensagem", text.encode())

    @classmethod
    def send_file(cls, path):
        with open(path, "rb") as f:
            cls._send_item("FILE", os.path.basename(path), f.read())

    @classmethod
    def send_dir(cls, path):
        path = os.path.abspath(path)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(path):
                for fn in files:
                    full = os.path.join(root, fn)
                    z.write(full, os.path.relpath(full, path))
        cls._send_item("DIR", os.path.basename(path) + ".zip", buf.getvalue())

    #recepcao

    @classmethod
    def receive(cls, mode="all", save_dir="."):
        """
        Processa UM item recebido chame num loop para escuta continua.
        mode: 'text' | 'file' | 'dir' | 'all'.
        - texto: retorna o conteudo
        - file/dir: salva em save_dir e retorna o caminho
        Retorna None se caiu a conexao o loop do usuario continua.
        """
        item = None
        while True:
            with cls._lock:
                for i, it in enumerate(cls._inbox):
                    if mode == "all" or it["op"] == mode.upper():
                        item = cls._inbox.pop(i)
                        break
            if item:
                break
            time.sleep(0.1)

        op, name, data, ip = item["op"], item["name"], item["data"], item["ip"]
        try:
            with open(cls._log_file, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} RECEBEU {op} {name} de {ip} "
                        f"({len(data)/1048576:.2f} MB)\n")
        except OSError:
            pass

        if op == "TEXT":
            texto = data.decode(errors="replace")
            print(f"[✓] Texto de {ip}: {texto[:100]}")
            return texto

        path = os.path.join(save_dir, name)
        if op == "DIR":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    z.extractall(save_dir)
                path = os.path.join(save_dir, name.replace(".zip", ""))
                print(f"[✓] dir de {ip} extraído em: {os.path.abspath(path)}")
            except zipfile.BadZipFile:
                print(f"[!] dir de {ip} corrompido.")
                return None
        else:
            with open(path, "wb") as f:
                f.write(data)
            print(f"[✓] file de {ip} salvo em: {os.path.abspath(path)}")
        return f"{op.lower()} '{name}' de {ip} salvo em {os.path.abspath(path)}"
