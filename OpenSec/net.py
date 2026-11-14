import socket
import struct
import subprocess
import platform
import time

try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


class Net:
    def __init__(self):
        self._me = self._get_local_ip()
        self._network, self._broadcast, self._netmask = self._calc_network()





#port scan 
# portas comuns para varrer
    COMMON_PORTS = [
        20, 21, 22, 23, 25, 26, 37, 53, 67, 68, 69, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 123, 135, 137, 138, 139, 143, 144, 161, 162, 179, 389, 427, 443,
        445, 465, 500, 514, 515, 520, 540, 548, 554, 587, 593, 623, 631, 636, 646,
        705, 873, 902, 990, 993, 995, 1080, 1099, 1194, 1234, 1241, 1293, 1311,
        1433, 1434, 1494, 1521, 1604, 1720, 1723, 1741, 1812, 1813, 1883, 1911,
        2000, 2020, 2049, 2065, 2100, 2121, 2123, 2222, 2375, 2376, 2379, 2380,
        2525, 2601, 2717, 2869, 3000, 3001, 3128, 3260, 3268, 3269, 3299, 3306,
        3389, 3531, 3690, 3784, 3785, 4321, 4444, 4445, 4567, 4700, 4848, 5000,
        5001, 5009, 5051, 5060, 5061, 5100, 5150, 5190, 5222, 5269, 5280, 5353,
        5432, 5480, 5489, 5555, 5560, 5672, 5666, 5718, 5800, 5810, 5900, 5901,
        5902, 5903, 5911, 5984, 5985, 5986, 6000, 6001, 6002, 6003, 6004, 6005,
        6379, 6443, 6588, 6666, 6667, 6668, 6669, 6881, 6900, 7000, 7001, 7002,
        7019, 7070, 7100, 7181, 7200, 7443, 7676, 7777, 8000, 8001, 8002, 8008,
        8009, 8010, 8020, 8021, 8023, 8030, 8040, 8045, 8080, 8081, 8082, 8083,
        8085, 8088, 8089, 8090, 8091, 8098, 8100, 8118, 8123, 8181, 8222, 8243,
        8280, 8333, 8383, 8400, 8443, 8500, 8600, 8642, 8800, 8812, 8899, 9000,
        9001, 9002, 9009, 9010, 9020, 9071, 9080, 9081, 9090, 9091, 9100, 9111,
        9200, 9255, 9256, 9418, 9500, 9503, 9875, 9981, 10000, 10180, 10215,
        10243, 10566, 10616, 10617, 10628, 11080, 11211, 12000, 12345, 13000,
        13722, 13782, 14000, 16000, 16113, 16993, 17200, 17988, 18101, 19150,
        20000, 20828, 21571, 24465, 24800, 25734, 27017, 27018, 27019, 28017,
        32764, 32773, 32913, 34129, 35513, 37215, 40193, 41523, 44176, 44443,
        44445, 45678, 47001, 49152, 49153, 49154, 49155, 49156, 49157, 49158,
        49159, 49160, 49161, 49163, 49167, 50000, 50003, 50050, 55555, 55666,
        61613, 61616, 65000, 65024,
    ]

    # servicos conhecidos: porta -> nome
    SERVICES = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        26: "rsftp", 37: "time", 53: "domain", 67: "dhcps", 68: "dhcpc",
        69: "tftp", 79: "finger", 80: "http", 81: "hosts2-ns", 88: "kerberos",
        106: "pop3pw", 110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp",
        123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
        139: "netbios-ssn", 143: "imap", 144: "news", 161: "snmp", 162: "snmptrap",
        179: "bgp", 389: "ldap", 427: "afp", 443: "https", 445: "microsoft-ds",
        465: "smtps", 500: "isakmp", 514: "syslog", 515: "printer", 520: "rip",
        540: "uucp", 548: "afp", 554: "rtsp", 587: "submission", 593: "http-rpc-epmap",
        623: "asf-rmcp", 631: "ipp", 636: "ldaps", 646: "ldp", 705: "atlas",
        873: "rsync", 902: "vmware-auth", 990: "ftps", 993: "imaps", 995: "pop3s",
        1080: "socks", 1099: "rmiregistry", 1194: "openvpn", 1234: "hotline",
        1241: "nessus", 1293: "pkd", 1311: "dell-idrac", 1433: "ms-sql-s",
        1434: "ms-sql-m", 1494: "citrix-ica", 1521: "oracle", 1604: "citrix",
        1720: "h323", 1723: "pptp", 1741: "cisco-aironet", 1812: "radius",
        1813: "radius-acct", 1883: "mqtt", 1911: "starlight", 2000: "cisco-sccp",
        2020: "xinupageserver", 2049: "nfs", 2065: "dlsrpn", 2100: "oracle-gk",
        2121: "proftpd", 2123: "l2tp", 2222: "ethernetip", 2375: "docker",
        2376: "docker-tls", 2379: "etcd-client", 2380: "etcd-peer",
        2525: "smtp-alt", 2601: "zebra", 2717: "pnrequests", 2869: "icslap",
        3000: "ppp/grafana", 3001: "mercury", 3128: "squid-proxy", 3260: "iscsi",
        3268: "globalcatLDAP", 3269: "globalcatLDAPssl", 3299: "saprouter",
        3306: "mysql", 3389: "ms-wbt-server", 3531: "aclp", 3690: "svn",
        3784: "ventrilo", 3785: "ventrilo", 4321: "rwhois", 4444: "krb524",
        4445: "upnotifyp", 4567: "tram", 4700: "questdb", 4848: "glassfish",
        5000: "upnp/flask", 5001: "synapse", 5009: "airport-admin", 5051: "ida",
        5060: "sip", 5061: "sip-tls", 5100: "admd", 5150: "atmp", 5190: "aim",
        5222: "jabber-client", 5269: "jabber-server", 5280: "xmpp-bosh",
        5353: "mdns", 5432: "postgresql", 5480: "vnc-http", 5489: "saphostctrl",
        5555: "adb", 5560: "isqlplus", 5672: "amqp", 5666: "nrpe", 5718: "dpm",
        5800: "vnc-http", 5810: "hpn", 5900: "vnc", 5901: "vnc-1", 5902: "vnc-2",
        5903: "vnc-3", 5911: "cpdlc", 5984: "couchdb", 5985: "winrm",
        5986: "winrm-tls", 6000: "x11", 6001: "x11-1", 6002: "x11-2", 6003: "x11-3",
        6004: "x11-4", 6005: "x11-5", 6379: "redis", 6443: "kubernetes",
        6588: "opera", 6666: "irc", 6667: "irc", 6668: "irc", 6669: "irc",
        6881: "bittorrent", 6900: "irc", 7000: "afs3", 7001: "weblogic",
        7002: "weblogic-ssl", 7019: "doceri", 7070: "realserver", 7100: "xfs",
        7181: "crudproxy", 7200: "fodms", 7443: "oracle-https", 7676: "imqbroker",
        7777: "cbt", 8000: "http-alt", 8001: "vcom", 8002: "teradataord",
        8008: "http", 8009: "ajp13", 8010: "http", 8020: "hadoop", 8021: "ftp",
        8023: "aricent", 8030: "hicp", 8040: "mars", 8045: "oxe", 8080: "http-proxy",
        8081: "blackice", 8082: "intellitrace", 8083: "us-srv", 8085: "m2ms",
        8088: "http-mc", 8089: "tornado", 8090: "opsmessaging", 8091: "jetscape",
        8098: "wkehybweb", 8100: "photuris", 8118: "privoxy", 8123: "polipo",
        8181: "intouch", 8222: "vmware", 8243: "synapse-tls", 8280: "synapse-http",
        8333: "bitcoin", 8383: "m2ms", 8400: "admd", 8443: "https-alt",
        8500: "consul", 8600: "asterisk", 8642: "park-agent", 8800: "sunwebadmin",
        8812: "cypress", 8899: "ospm", 9000: "cslistener", 9001: "tor-orport",
        9002: "tor-socks", 9009: "pichat", 9010: "sdr", 9020: "tor-trans",
        9071: "tor-dns", 9080: "glrpc", 9081: "cisco-aqos", 9090: "websm",
        9091: "transmission", 9100: "jetdirect", 9111: "hp-pdl", 9200: "elasticsearch",
        9255: "mon", 9256: "mon", 9418: "git", 9500: "ismserver", 9503: "mua",
        9875: "sessiondirector", 9981: "empire", 10000: "webmin",
        10180: "mcxilr", 10215: "hip5", 10243: "apc-device", 10566: "pentaho",
        10616: "qregRem", 10617: "cadriley", 10628: "postgres-admin", 11080: "streamtv",
        11211: "memcached", 12000: "dbcool", 12345: "netbus", 13000: "questnote",
        13722: "netbackup", 13782: "vbackup", 14000: "soid", 16000: "avterm",
        16113: "sflow", 16993: "amt-broadband", 17200: "isafe", 17988: "flr-agent",
        18101: "omnivision", 19150: "gkrellm", 20000: "dnp/usermin", 20828: "nuclear",
        21571: "rdmnet", 24465: "hpvmmcontrol", 24800: "synergy", 25734: "nassh",
        27017: "mongodb", 27018: "mongodb-2", 27019: "mongodb-3", 28017: "mongodb-web",
        32764: "broadcom-backdoor", 32773: "fidnet", 32913: "proxim", 34129: "sensus",
        35513: "ieee8021x", 37215: "homeboi", 40193: "novell-ag", 41523: "dcap",
        44176: "commtouch", 44443: "coldfusion-auth", 44445: "tinyfw", 45678: "rsyslog",
        47001: "winrm-http", 49152: "ms-ollp", 49153: "ms-ollp", 49154: "ms-ollp",
        49155: "ms-ollp", 49156: "ms-ollp", 49157: "ms-ollp", 49158: "ms-ollp",
        49159: "ms-ollp", 49160: "ms-ollp", 49161: "ms-ollp", 49163: "ms-ollp",
        49167: "ms-ollp", 50000: "iiimsf", 50003: "skylinks", 50050: "metasploit",
        55555: "dces Quic", 55666: "unknown", 61613: "stomp", 61616: "activemq",
        65000: "eocs", 65024: "nvid",
    }  


# monitor de trafego

    _HISTORY = []          # linhas ja capturadas
    _HISTORY_MAX = 500     # limite de linhas guardadas
    _flow_bytes = {}       # calcular a velocidade 

    @classmethod
    def static(cls, clear_screen=False, sample_time=1.0):
        
        packets = cls._capture(sample_time)
        rows = cls._packets_to_rows(packets)

        if clear_screen:
            print("\033[2J\033[H", end="")

        header = f"{'IP':<16}{'Porta':<10}{'Servico':<14}{'Velocidade':<12}{'Destino':<22}{'Estado'}"
        print(header)
        print("-" * len(header))
        for r in cls._HISTORY:
            print(r)
        return rows

    @classmethod
    def static_full(cls, interval=1.0):
        
        print("[*] Capturando trafego... Ctrl+C para parar.\n")
        try:
            while True:
                cls.static(clear_screen=True, sample_time=interval)
        except KeyboardInterrupt:
            print("\n[!] Captura encerrada pelo usuario.")

   

    @classmethod
    def _capture(cls, timeout):

        if _HAS_SCAPY:
            try:
                from scapy.all import sniff
                return sniff(timeout=timeout, iface="wlan0", store=True)
            except Exception:
                pass
        
        try:
            out = subprocess.check_output(
                ["tcpdump", "-i", "wlan0", "-nn", "-c", "200",
                 "-G", str(timeout), "-W", "1"],
                text=True, stderr=subprocess.DEVNULL, timeout=timeout + 2)
            return out  
        except Exception:
            return []

    @classmethod
    def _packets_to_rows(cls, packets):
        
        import datetime
        now = time.time()
        rows = []

        if isinstance(packets, str):
            for line in packets.splitlines():
                rows.append(f"{line[:100]}")
            cls._append_history(rows)
            return rows

        new_speeds = {}
        for pkt in packets:
            ip_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")
            if ip_layer is None:
                continue  
            src, dst = ip_layer.src, ip_layer.dst
            proto = "other"
            sport = dport = 0
            if pkt.haslayer("TCP"):
                sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
                proto = "tcp"
            elif pkt.haslayer("UDP"):
                sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
                proto = "udp"
            elif pkt.haslayer("ICMP"):
                proto = "icmp"

            size = len(pkt)
            flow = (src, sport, dst, dport)
            
            old = cls._flow_bytes.get(flow, (0, now - 1))
            new_speeds[flow] = new_speeds.get(flow, 0) + size
            cls._flow_bytes[flow] = (old[0] + size, now)

            service = cls.SERVICES.get(dport) or cls.SERVICES.get(sport) or proto.upper()
            if proto == "icmp":
                service = "ICMP/ping"
            speed = new_speeds[flow] / max(now - old[1], 0.1)  # bytes/s aproximado
            state = "Conectado" if proto in ("tcp", "udp") else "Ativo"

            rows.append(
                f"{src:<16}{f'{dport or sport}/{proto}':<10}{service:<14}"
                f"{cls._fmt_speed(speed):<12}{f'{dst}:{dport}' if dport else dst:<22}{state}"
            )
        cls._append_history(rows)
        return rows

    @classmethod
    def _append_history(cls, rows):
        cls._HISTORY.extend(rows)
        if len(cls._HISTORY) > cls._HISTORY_MAX:
            cls._HISTORY = cls._HISTORY[-cls._HISTORY_MAX:]

    @classmethod
    def _port_service(cls, port):
        if not port:
            return None
        return cls.SERVICES.get(port)

    @staticmethod
    def _fmt_speed(bps):
        if bps <= 0:
            return "0 b/s"
        for unit in ("b/s", "Kb/s", "Mb/s", "Gb/s"):
            if bps < 1024:
                return f"{bps:.0f} {unit}" if unit == "b/s" else f"{bps:.1f} {unit}"
            bps /= 1024
        return f"{bps:.1f} Tb/s"    


#deteccao de SO

    @classmethod
    def list_SO(cls, ip):
        
        if isinstance(ip, (list, tuple, set)):
            return {t: cls.list_SO(t) for t in ip}

        target = str(ip)
        details = {}
        ttl = cls._get_ttl(target)
        guess, confidence = "desconhecido", 0

        if ttl is not None:
            details["ttl"] = ttl
          
            if ttl <= 64:
                guess, confidence = "Linux/Unix/macOS", 60
                if ttl in (64, 63, 62, 61, 60, 59, 58, 57, 56, 55):
                    confidence = 75
            elif ttl <= 128:
                guess, confidence = "Windows", 70
                if ttl in (128, 127, 126, 125):
                    confidence = 85
            elif ttl <= 255:
                guess, confidence = "Equipamento de rede (roteador/switch)", 70

        
        open_ports = cls.ports(target)
        for port, service in open_ports.items():
            banner = (service or "").lower()
            if "windows" in banner or "iis" in banner or "microsoft" in banner:
                guess, confidence = "Windows", 95
                details["evidencia"] = banner
                break
            if "ubuntu" in banner or "debian" in banner or "linux" in banner:
                guess, confidence = "Linux", 95
                details["evidencia"] = banner
                break
            if "openssh" in banner:
               
                if guess == "Windows" and confidence < 95:
                    guess, confidence = "Windows ou Linux (OpenSSH)", 50
                elif confidence < 90:
                    guess, confidence = "Linux/Unix (OpenSSH)", 85
                    details["evidencia"] = banner
            if port == 3389:  
                guess, confidence = "Windows", 90
                details["evidencia"] = "porta 3389 (RDP) aberta"
            if port == 445 and guess.startswith("Linux"):
                details["smb"] = True

        return {"so": guess, "confianca": f"{confidence}%", "detalhes": details}

    @staticmethod
    def _get_ttl(ip):
        
        param = "-n" if platform.system() == "Windows" else "-c"
        try:
            out = subprocess.check_output(["ping", param, "1", "-W", "1", ip],
                                          stderr=subprocess.DEVNULL, text=True,
                                          timeout=3).lower()
            import re
            m = re.search(r"ttl[=: ]+(\d+)", out)
            if m:
                return int(m.group(1))
        except Exception:
            pass
       
        if _HAS_SCAPY:
            try:
                from scapy.all import IP, TCP, sr1
                for dport in (80, 443, 22):
                    resp = sr1(IP(dst=ip) / TCP(dport=dport, flags="S"),
                               timeout=2, verbose=False)
                    if resp and resp.haslayer(IP):
                        return resp[IP].ttl
            except Exception:
                pass
        return None  

    @classmethod
    def ports(cls, ip, port_range=None, timeout=1.0):
        
        
        if isinstance(ip, (list, tuple, set)):
            result = {}
            for target in ip:
                result[target] = cls.ports(target, port_range, timeout)
            return {k: v for k, v in result.items() if v}  

        target = str(ip)
        ports = cls._resolve_ports(port_range)
        open_ports = {}

        import concurrent.futures
        def probe(port):
            if cls._tcp_connect(target, port, timeout):
                service = cls._identify(target, port)
                return port, service
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            for r in ex.map(probe, ports):
                if r:
                    open_ports[r[0]] = r[1]
        return dict(sorted(open_ports.items()))

    @classmethod
    def _resolve_ports(cls, port_range):
        if port_range is None:
            return cls.COMMON_PORTS
        if isinstance(port_range, (tuple, list)) and len(port_range) == 2:
            return list(range(port_range[0], port_range[1] + 1))
        if isinstance(port_range, int):
            return [port_range]
        return cls.COMMON_PORTS

    @staticmethod
    def _tcp_connect(ip, port, timeout) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except OSError:
            return False

    @classmethod
    def _identify(cls, ip, port) -> str:
       
        banner = cls._grab_banner(ip, port)
        if banner:
            return banner.strip().split("\n")[0][:60]
        return cls.SERVICES.get(port, "unknown")

    @staticmethod
    def _grab_banner(ip, port, timeout=1.0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                
                if port in (80, 443, 8080, 8443):
                    s.sendall(b"GET / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
                s.settimeout(timeout)
                data = s.recv(256)
                return data.decode(errors="replace").strip() or None
        except (OSError, UnicodeDecodeError):
            return None    


#versao de servicos

    
    VERSION_PATTERNS = [
        (r"SSH-[\d.]+-(\S+?)[_\s]", "ssh"),
        (r"(?:Apache)/([\d.]+)", "apache"),
        (r"Server:\s*nginx/([\d.]+)", "nginx"),
        (r"Microsoft-IIS/([\d.]+)", "iis"),
        (r"(?:Redis)\s*v?([\d.]+)", "redis"),
        (r"(?:MySQL)\s*([\d.]+)", "mysql"),
        (r"PostgreSQL\s*([\d.]+)", "postgresql"),
        (r"MongoDB.*?([\d]+\.[\d]+)", "mongodb"),
        (r"vsftpd\s*([\d.]+)", "vsftpd"),
        (r"ProFTPD\s*([\d.]+)", "proftpd"),
        (r"Exim\s*([\d.]+)", "exim"),
        (r"Postfix", "postfix"),
        (r"(?:lighttpd)/([\d.]+)", "lighttpd"),
        (r"Caddy", "caddy"),
        (r"Memcached\s*v?([\d.]+)", "memcached"),
        (r"Elasticsearch\s*\(?([\d.]+)", "elasticsearch"),
        (r" twisted/([\d.]+)", "twisted"),
    ]

    @classmethod
    def ports_version(cls, ip, port_range=None, timeout=1.0):
        
        if isinstance(ip, (list, tuple, set)):
            result = {}
            for t in ip:
                result[t] = cls.ports_version(t, port_range, timeout)
            return {k: v for k, v in result.items() if v}

        target = str(ip)
        ports = cls._resolve_ports(port_range)
        import concurrent.futures

        def probe(port):
            if not cls._tcp_connect(target, port, timeout):
                return None
            banner = cls._grab_banner_deep(target, port)
            service = cls.SERVICES.get(port, "unknown")
            version = cls._extract_version(port, banner)
            return port, {"servico": service, "versao": version, "banner": banner}

        open_ports = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            for r in ex.map(probe, ports):
                if r:
                    open_ports[r[0]] = r[1]
        return dict(sorted(open_ports.items()))

    @staticmethod
    def _grab_banner_deep(ip, port, timeout=1.5):
       
        probes = {
            80:   b"GET / HTTP/1.1\r\nHost: %b\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % ip.encode(),
            443:  None, 
            8080: b"GET / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode(),
            21:   None,  
            22:   None,  
            25:   None,
            587:  None,
            110:  None,
            143:  None,
            6379: b"INFO server\r\n",
            3306: None,
        }
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                probe = probes.get(port)
                if probe:
                    s.sendall(probe)
                s.settimeout(timeout)
                data = s.recv(512)
                return data.decode(errors="replace").strip()
        except (OSError, UnicodeDecodeError):
            return None

    @classmethod
    def _extract_version(cls, port, banner):
       
        if not banner:
            return None
        import re
        for pattern, svc in cls.VERSION_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                return f"{svc} {m.group(1)}" if m.lastindex else svc
       
        m = re.search(r"(\S+)[/ _-]?v?(\d+\.\d+(?:\.\d+)?)", banner)
        if m:
            return f"{m.group(1).strip('/ ')} {m.group(2)}"
        return None

        
    #info da maquina

    @staticmethod
    def _get_local_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except OSError:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    @staticmethod
    def _calc_network() -> tuple:
        #rede, broadcast, mascara — o codigo assume /24, igual a sua wlan0
        ip = Net._get_local_ip()
        mask = 0xFFFFFF00  
        ipi = struct.unpack(">I", socket.inet_aton(ip))[0]
        network = socket.inet_ntoa(struct.pack(">I", ipi & mask))
        broadcast = socket.inet_ntoa(struct.pack(">I", ipi | (~mask & 0xFFFFFFFF)))
        return (network, broadcast, "255.255.255.0")

    
    @classmethod
    def _ensure(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = cls()
        return cls._instance

    @classmethod
    def _hosts_range(cls):
        net = cls._ensure()
        net_i = struct.unpack(">I", socket.inet_aton(net._network))[0]
        bc_i = struct.unpack(">I", socket.inet_aton(net._broadcast))[0]
        return [socket.inet_ntoa(struct.pack(">I", i)) for i in range(net_i + 1, bc_i)]

    @classmethod
    def list_me(cls) -> list:
        
        net = cls._ensure()
        hosts = [net._me]
        found = cls._arp_scan()
        for ip in sorted(found):
            if ip != net._me:
                hosts.append(ip)
        return hosts

    @classmethod
    def list_me_mac(cls) -> dict:
        
        net = cls._ensure()
        result = {net._me: None}
        result.update({ip: mac for ip, mac in cls._arp_scan().items() if ip != net._me})
        return result

    #ARP scan

    @classmethod
    def _arp_scan(cls) -> dict:
        
        net = cls._ensure()
        if not _HAS_SCAPY:
            return cls._arp_scan_fallback()
        target = f"{net._network}/24"
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
                          timeout=3, iface="wlan0", verbose=False)
        return {rcv.psrc: rcv.hwsrc for _, rcv in answered}

    @classmethod
    def _arp_scan_fallback(cls) -> dict:
       
        import concurrent.futures
        param = "-n" if platform.system() == "Windows" else "-c"

        def ping(ip):
            return subprocess.run(["ping", param, "1", "-W", "1", ip],
                                  capture_output=True).returncode == 0

        ips = cls._hosts_range()
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            alive = [ip for ip, ok in zip(ips, ex.map(ping, ips)) if ok]
        
        out = subprocess.check_output(["ip", "neigh"] if platform.system() != "Windows"
                                      else ["arp", "-a"], text=True)
        macs = {}
        for line in out.splitlines():
            for ip in alive:
                if ip in line:
                    parts = line.split()
                    mac = next((p for p in parts if p.count(":") == 5), None)
                    if mac and mac != "ff:ff:ff:ff:ff:ff" and "INCOMPLETE" not in line:
                        macs[ip] = mac
        return macs



@property
def me(self) -> str:
    return self._me
Net.me = me
