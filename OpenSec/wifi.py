import os
import re
import time
import shutil
import subprocess
import tempfile

def _run(cmd, timeout=10):
  #Roda comando
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT,
                                      timeout=timeout)
        return True, out
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, getattr(e, "output", "") or str(e)


class DHCP:
    """
    Cria um access point Wi-Fi completo:
    hostapd AP + dnsmasq DHCP/DNS + iptables compartilha internet da WAN.

    Exemplo:
        dhcp = Wifi.DHCP()
        dhcp.conf = {
            "name": "MinhaRede", "password": "senha12345",
            "IP_inicial": "192.168.1.100", "IP_final": "192.168.1.119",
            "Mascara": "255.255.255.0", "Gateway": "192.168.1.1",
            "DNS_Primario": "8.8.8.8", "DNS_Secundario": "8.8.4.4",
            "Lease_Time": 86400,
        }
        dhcp.wlan0()          # interface Wi-Fi que servira o AP
        dhcp.eth0()           # interface com internet WAN
        dhcp.iptables_set()   # regras de encaminhamento/NAT
        dhcp.start()          # sobe tudo
        dhcp.stop()           # derruba tudo
    """
    def __init__(self):
        self.conf = {
            "name": "OpenSec",
            "password": "opensec123",
            "IP_inicial": "192.168.1.100",
            "IP_final": "192.168.1.119",
            "Mascara": "255.255.255.0",
            "Gateway": "192.168.1.1",
            "DNS_Primario": "8.8.8.8",
            "DNS_Secundario": "8.8.4.4",
            "Lease_Time": 86400,
        }
        self.ap_iface = "wlan0"      # interface que vai servir o AP (dhcp.wlan0())
        self.wan_iface = "eth0"      # interface com internet (dhcp.eth0())
        self._tmp = tempfile.mkdtemp(prefix="opensec_wifi_")
        self._running = False

    #configuracao de interfaces

    def wlan0(self, iface=None):
     #   """Define a interface Wi-Fi que servira o AP (padrao: wlan0)
        if iface:
            self.ap_iface = iface
        return self.ap_iface

    def eth0(self, iface=None):
      #  Define a interface WAN com internet Padrao: eth0; None = auto-deteta
        if iface:
            self.wan_iface = iface
        else:
            self.wan_iface = self._detect_wan()
        return self.wan_iface

    def _detect_wan(self):
      #  """Descobre a interface que tem rota default a com internet
        ok, out = _run(["ip", "route"])
        if ok:
            m = re.search(r"default via \S+ dev (\S+)", out)
            if m:
                return m.group(1)
        return "eth0"

    # iptables / forwarding

    def iptables_set(self):
      #Ativa IP forwarding e NAT: clientes do AP saem pela WAN
        gw = self.conf["Gateway"]
        _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        rules = [
            ["iptables", "-t", "nat", "-A", "POSTROUTING",
             "-o", self.wan_iface, "-j", "MASQUERADE"],
            ["iptables", "-A", "FORWARD", "-i", self.ap_iface,
             "-o", self.wan_iface, "-j", "ACCEPT"],
            ["iptables", "-A", "FORWARD", "-i", self.wan_iface,
             "-o", self.ap_iface, "-m", "state",
             "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ]
        for r in rules:
            ok, out = _run(r)
            if not ok:
                print(f"[!] iptables falhou: {' '.join(r)} -> {out.strip()}")
        # endereca a interface do AP com o gateway escolhido
        _run(["ip", "addr", "add", f"{gw}/24", "dev", self.ap_iface])
        _run(["ip", "link", "set", self.ap_iface, "up"])
        print(f"[*] NAT ativado: {self.ap_iface} -> internet via {self.wan_iface}")

    def iptables_clear(self):
        #Remove as regras criadas ao parar o AP
        _run(["iptables", "-t", "nat", "-D", "POSTROUTING",
              "-o", self.wan_iface, "-j", "MASQUERADE"])
        _run(["iptables", "-D", "FORWARD", "-i", self.ap_iface,
              "-o", self.wan_iface, "-j", "ACCEPT"])
        _run(["iptables", "-D", "FORWARD", "-i", self.wan_iface,
              "-o", self.ap_iface, "-m", "state",
              "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        print("[*] Regras de NAT removidas.")

    #arquivos de configuracao

    def _write_hostapd(self):
        #Gera /tmp/opensec_wifi_/hostapd.conf a partir do self.conf
        pw = self.conf.get("password", "")
        lines = [
            f"interface={self.ap_iface}",
            "driver=nl80211",
            f"ssid={self.conf['name']}",
            "hw_mode=g",
            "channel=6",
            "auth_algs=1",
            "wmm_enabled=0",
        ]
        if pw:
            if len(pw) < 8:
                raise ValueError("senha WPA precisa de no mínimo 8 caracteres")
            lines += [
                "wpa=2", "wpa_key_mgmt=WPA-PSK",
                f"wpa_passphrase={pw}", "wpa_pairwise=TKIP CCMP",
                "rsn_pairwise=CCMP",
            ]
        else:
            lines.append("auth_algs=1")  # rede aberta
        path = os.path.join(self._tmp, "hostapd.conf")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def _write_dnsmasq(self):
        #Gera dnsmasq.conf com o range gateway e DNS do self.conf
        c = self.conf
        lines = [
            f"interface={self.ap_iface}",
            "bind-interfaces",
            f"dhcp-range={c['IP_inicial']},{c['IP_final']},{c['Mascara']},{int(c['Lease_Time'])}",
            f"dhcp-option=3,{c['Gateway']}",          # gateway
            f"dhcp-option=6,{c['DNS_Primario']},{c['DNS_Secundario']}",  # DNS
            "dhcp-authoritative",
            "server=8.8.8.8",  # DNS upstream p/ o proprio AP
        ]
        path = os.path.join(self._tmp, "dnsmasq.conf")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path

    #ciclo de vida
    
    def start(self):
        #"""Sobe hostapd + dnsmasq com as configs definidas
        if self._running:
            print("[!] Access point já está ativo.")
            return
        missing = [t for t in ("hostapd", "dnsmasq") if not shutil.which(t)]
        if missing:
            print(f"[!] Instale: sudo apt install {' '.join(missing)}")
            return

        # mata instancias do sistema para nao brigar de porta/interface
        _run(["pkill", "-f", "hostapd.*opensec"], timeout=3)
        _run(["pkill", "-f", "dnsmasq.*opensec"], timeout=3)
        time.sleep(1)

        hconf = self._write_hostapd()
        dconf = self._write_dnsmasq()

        log_h = open(os.path.join(self._tmp, "hostapd.log"), "w")
        log_d = open(os.path.join(self._tmp, "dnsmasq.log"), "w")
        self._hproc = subprocess.Popen(["hostapd", hconf], stdout=log_h, stderr=log_h)
        time.sleep(2)  # hostapd precisa estar no ar antes do dnsmasq
        self._dproc = subprocess.Popen(["dnsmasq", "--no-daemon", f"--pid-file={self._tmp}/dnsmasq.pid",
                                        "-C", dconf], stdout=log_d, stderr=log_d)

        self._running = True
        print(f"[*] Access point '{self.conf['name']}' ativo em {self.ap_iface}")
        print(f"    Gateway: {self.conf['Gateway']} | DHCP: {self.conf['IP_inicial']}"
              f"-{self.conf['IP_final']} | Lease: {int(self.conf['Lease_Time'])}s")
        print(f"    Internet via {self.wan_iface} | logs: {self._tmp}/")

        # se qualquer um morrer avisa
        if self._hproc.poll() is not None:
            print("[!] hostapd falhou ao iniciar — veja hostapd.log "
                  "(ex: interface em uso pelo NetworkManager).")
            self._running = False
            return

    def stop(self):
        #"""Derruba AP DHCP e regras de NAT"""
        for attr in ("_hproc", "_dproc"):
            p = getattr(self, attr, None)
            if p and p.poll() is None:
                p.terminate()
        self._running = False
        self.iptables_clear()
        print("[*] Access point parado.")

    def clients(self):
       # """Clientes conectados ao AP: [(ip, mac), ...]
        leases = "/var/lib/misc/dnsmasq.leases"
        result = []
        try:
            with open(leases) as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 3:
                        result.append((p[2], p[1]))  # ip, mac
        except FileNotFoundError:
            pass
        return result


class Wifi:
    #"""Informacoes da rede Wi-Fi atual nao e o DHCP — e consulta)

    @staticmethod
    def status():
        """
        Configuracoes da rede a qual estamos conectados:
        SSID, frequencia, canal, sinal, IP, gateway, DNS.
        """
        info = {}
        # iw (mais completo, precisa root para alguns detalhes)
        ok, out = _run(["iw", "dev", "wlan0", "link"])
        if ok:
            m = re.search(r"SSID:\s*(.+)", out)
            info["ssid"] = m.group(1).strip() if m else None
            m = re.search(r"freq:\s*(\d+)", out)
            if m:
                info["frequencia"] = f"{m.group(1)} MHz"
            m = re.search(r"signal:\s*(-?\d+)", out)
            if m:
                info["sinal"] = f"{m.group(1)} dBm"
        # iwgetid fallback
        if "ssid" not in info:
            ok, out = _run(["iwgetid", "-r"])
            if ok:
                info["ssid"] = out.strip() or None
        # IP/gateway/DNS da interface
        ok, out = _run(["ip", "-4", "addr", "show", "wlan0"])
        if ok:
            m = re.search(r"inet (\S+)/(\d+)", out)
            if m:
                info["ip"] = m.group(1)
                info["cidr"] = f"/{m.group(2)}"
        ok, out = _run(["ip", "route"])
        if ok:
            m = re.search(r"default via (\S+) dev (\S+)", out)
            if m:
                info["gateway"] = m.group(1)
                info["interface"] = m.group(2)
        dns = []
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns.append(line.split()[1])
        except FileNotFoundError:
            pass
        info["dns"] = dns
        return info

    @staticmethod
    def list_ips():
    
        from .net import Net
        return Net.list_me()

    @staticmethod
    def list_macs():
    
        from .net import Net
        return Net.list_me_mac()
