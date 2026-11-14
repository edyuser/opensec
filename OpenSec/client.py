import socket
import os
import io
import time
import zipfile

def _fmt(bps):
    for u in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024:
            return f"{bps:.1f} {u}"
        bps /= 1024
    return f"{bps:.1f} TB/s"


class Client:
    #Cliente TCP com reconexao automática ate 3 tentativas
    _sock = None
    _host = None
    _port = None

    #conexao

    @classmethod
    def connect(cls, ip, port, timeout=5):
        cls._host, cls._port = ip, port
        return cls._connect(timeout)

    @classmethod
    def _connect(cls, timeout=5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((cls._host, cls._port))
            s.settimeout(None)  # modo bloqueante apos conectar
            cls._sock = s
            print(f"[*] Conectado a {cls._host}:{cls._port}")
            return True
        except OSError as e:
            print(f"[!] Falha: {e}")
            return False

    @classmethod
    def _ensure(cls):
        # Garante conexao viva reconecta ate 3x
        if cls._sock:
            try:
                cls._sock.getpeername()
                return True
            except OSError:
                cls._sock = None
        for _ in range(3):
            if cls._connect():
                return True
            time.sleep(1)
        raise ConnectionError("não foi possível reconectar")

    #envio

    @classmethod
    def _send_item(cls, op, name, data):
        cls._ensure()
        try:
            cls._sock.sendall(f"{op}|{len(data)}|{name}\n".encode())
            resp = cls._sock.recv(4)
            if b"OK" not in resp:
                print("[!] Rejeitado pelo servidor.")
                return False
            t0, sent = time.time(), 0
            total = len(data)
            for i in range(0, total, 65536):
                cls._sock.sendall(data[i:i+65536])
                sent += len(data[i:i+65536])
                el = max(time.time() - t0, 0.001)
                print(f"\r[↑] {sent/1048576:.2f}/{total/1048576:.2f} MB  "
                      f"{_fmt(sent/el)}   ", end="", flush=True)
            el = max(time.time() - t0, 0.001)
            print(f"\r[↑] {total/1048576:.2f} MB enviados  {_fmt(total/el)}          ")
            return True
        except OSError:
            print("[!] Conexão caiu — reconectando...")
            cls._sock = None
            if cls._ensure():
                return cls._send_item(op, name, data)
            return False

    @classmethod
    def send_text(cls, text):
        return cls._send_item("TEXT", "mensagem", text.encode())

    @classmethod
    def send_file(cls, path):
        with open(path, "rb") as f:
            return cls._send_item("FILE", os.path.basename(path), f.read())

    @classmethod
    def send_dir(cls, path):
        #Zipa o diretorio em memoria e envia como DIR
        
        path = os.path.abspath(path)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(path):
                for fn in files:
                    full = os.path.join(root, fn)
                    z.write(full, os.path.relpath(full, path))
        return cls._send_item("DIR", os.path.basename(path) + ".zip", buf.getvalue())

    # ---------- recepcao ----------

    @classmethod
    def receive(cls, mode="all", save_dir="."):
        """
        Recebe UM item do servidor. mode: 'text'|'file'|'dir'|'all'.
        Chame num loop para escuta continua.
        """
        cls._ensure()
        header = b""
        while not header.endswith(b"\n"):
            c = cls._sock.recv(1)
            if not c:
                raise ConnectionError("servidor fechou")
            header += c
        op, size, name = header.decode().strip().split("|", 2)
        size = int(size)

        if mode != "all" and op != mode.upper():
            # le e descarta o payload para nao desincronizar o protocolo
            cls._sock.sendall(b"REJEITADO\n")
            got = 0
            while got < size:
                got += len(cls._sock.recv(min(65536, size - got)))
            return f"[descartado] tipo {op} não aceito (modo={mode})"

        cls._sock.sendall(b"OK\n")
        data, t0 = b"", time.time()
        while len(data) < size:
            chunk = cls._sock.recv(min(65536, size - len(data)))
            if not chunk:
                raise ConnectionError("conexão caiu durante a transferência")
            data += chunk
            el = max(time.time() - t0, 0.001)
            print(f"\r[↓] {len(data)/1048576:.2f}/{size/1048576:.2f} MB  "
                  f"{_fmt(len(data)/el)}   ", end="", flush=True)
        el = max(time.time() - t0, 0.1)
        print(f"\r[↓] {size/1048576:.2f} MB recebidos  {_fmt(size/el)}          ")

        if op == "TEXT":
            return data.decode(errors="replace")

        path = os.path.join(save_dir, name)
        if op == "DIR":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(save_dir)
            path = os.path.join(save_dir, name.replace(".zip", ""))
        else:
            with open(path, "wb") as f:
                f.write(data)
        print(f"[✓] {op.lower()} salvo em: {os.path.abspath(path)}")
        return f"{op.lower()} '{name}' salvo em {os.path.abspath(path)}"
