# OpenSec/melicry.py
import os
import base64
import hashlib
import secrets

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise ImportError("MelisaCry precisa da biblioteca 'cryptography': pip install cryptography")

_ENC_EXT = ".melisa"


class MelisaCry:

    _engine = "FERNET"

    # selecao de engine

    @classmethod
    def use(cls, engine):
        #Define o algoritmo: 'Fernet' ou 'AES'."""
        
        nome = str(getattr(engine, "__name__", engine)).upper()
        if nome not in ("FERNET", "AES"):
            raise ValueError(f"engine desconhecida: {engine} (use 'Fernet' ou 'AES')")
        cls._engine = nome
        return cls

    # chave

    class Key(str):
  #      Chave que lembra o caminho do arquivo de onde veio."""
        caminho = None

        @classmethod
        def de(cls, valor, caminho=None):
            k = cls(valor)
            k.caminho = caminho
            return k

    @staticmethod
    def _gerar():
   #     Gera uma chave nova base64, 32 bytes"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()

    @classmethod
    def key(cls, caminho="chave.txt"):
        
        if os.path.exists(caminho):
            with open(caminho, "r", encoding="utf-8") as f:
                valor = f.read().strip()
            if not valor:
                valor = cls._gerar()
                cls._salvar(caminho, valor)
            return cls.Key.de(valor, caminho)

        valor = cls._gerar()
        cls._salvar(caminho, valor)
        return cls.Key.de(valor, caminho)

    @staticmethod
    def _salvar(caminho, valor):
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(valor)

    @staticmethod
    def _resolver(chave):
       
        caminho = getattr(chave, "caminho", None)
        valor = str(chave).strip()
        if os.path.sep in valor or os.path.exists(valor):
            
            if os.path.exists(valor):
                with open(valor, "r", encoding="utf-8") as f:
                    valor = f.read().strip()
                caminho = valor 
        
        try:
            bruto = base64.urlsafe_b64decode(valor)
            if len(bruto) != 32:
                raise ValueError
        except Exception:
            raise ValueError("chave inválida: passe MelisaCry.key(), a string da chave "
                             "ou o caminho do arquivo de chave")
        return valor, caminho

    # operacoes

    @classmethod
    def crypt(cls, caminho):
        return cls._Operacao(caminho, cifrar=True)

    @classmethod
    def decrypt(cls, caminho):
       
        return cls._Operacao(caminho, cifrar=False)

    class _Operacao:
        def __init__(self, caminho, cifrar):
            self.caminho = caminho
            self.cifrar = cifrar

        def by_key(self, chave):
            
            chave_b64, caminho_chave = MelisaCry._resolver(chave)
            engine = MelisaCry._engine
            bruto = base64.urlsafe_b64decode(chave_b64)

            if engine == "FERNET":
                fernet = Fernet(chave_b64.encode())
                aesgcm = None
            else:
                fernet = None
                aesgcm = AESGCM(hashlib.sha256(bruto).digest())  # 32 bytes p/ AES-256-GCM

            alvo = self.caminho
            if os.path.isfile(alvo):
                arquivos = [alvo]
            elif os.path.isdir(alvo):
                arquivos = []
                for raiz, dirs, nomes in os.walk(alvo):
                    for n in nomes:
                        arquivos.append(os.path.join(raiz, n))
            else:
                return {"erro": f"caminho não encontrado: {alvo}"}

            ok, erros, pulados = [], {}, []

            for arquivo in arquivos:
                # Impedir ele de cifrar a chave e o proprio modulo
                if caminho_chave and os.path.abspath(arquivo) == os.path.abspath(caminho_chave):
                    pulados.append(arquivo)
                    continue
                if os.path.abspath(arquivo) == os.path.abspath(os.path.join(os.getcwd(), "chave.txt")):
                    pulados.append(arquivo)
                    continue

                cifrado = arquivo.endswith(_ENC_EXT)

                if self.cifrar and cifrado:
                    pulados.append(arquivo)      
                    continue
                if not self.cifrar and not cifrado:
                    pulados.append(arquivo)      
                    continue

                destino = (arquivo + _ENC_EXT) if self.cifrar else arquivo[:-len(_ENC_EXT)]

                try:
                    with open(arquivo, "rb") as f:
                        dados = f.read()

                    if engine == "FERNET":
                        if self.cifrar:
                            novo = fernet.encrypt(dados)
                        else:
                            novo = fernet.decrypt(dados)
                    else:  
                        if self.cifrar:
                            nonce = secrets.token_bytes(12)
                            novo = nonce + aesgcm.encrypt(nonce, dados, None)
                        else:
                            nonce, corpo = dados[:12], dados[12:]
                            novo = aesgcm.decrypt(nonce, corpo, None)

                    with open(destino, "wb") as f:
                        f.write(novo)

                    if self.cifrar:
                        os.remove(arquivo)      

                    ok.append(destino if self.cifrar else destino)
                except InvalidToken:
                    erros[arquivo] = "chave errada para este arquivo (InvalidToken)"
                except Exception as e:
                    erros[arquivo] = str(e)

            return {
                "engine": engine,
                "operacao": "cifrar" if self.cifrar else "decifrar",
                "alvo": self.caminho,
                "arquivos_ok": ok,
                "erros": erros,
                "pulados": pulados,
                "total": len(ok),
            }
