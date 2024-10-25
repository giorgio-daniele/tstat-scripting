import os
import re
import enum
import pandas
import ipaddress

class Document(enum.Enum):
    LOG_TCP_COMPLETE = 1
    LOG_TCP_PERIODIC = 2
    LOG_UDP_COMPLETE = 3
    LOG_UDP_PERIODIC = 4


class Protocol(enum.Enum):
    TCP = 1
    UDP = 2

LOG_TCP_COMPLETE = "log_tcp_complete"
LOG_TCP_PERIODIC = "log_tcp_periodic"
LOG_UDP_COMPLETE = "log_udp_complete"
LOG_UDP_PERIODIC = "log_udp_periodic"
LOG_HAR_COMPLETE = "log_har_complete"
LOG_BOT_COMPLETE = "log_bot_complete"
LOG_NET_COMPLETE = "log_net_complete"
LOG_VIDEO_COMPLETE = "log_video_complete"
LOG_AUDIO_COMPLETE = "log_audio_complete"

CAP = ".pcap"
BOT = ".csv"
HAR = ".har"

TSTAT_BINARY = "tstat/tstat/tstat"
TSTAT_CONFIG = "tstat/tstat-conf/runtime.conf"
TSTAT_GLOBAL = "tstat/tstat-conf/globals.conf"

def __private_address(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def __reserved_address(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def __is_dns_port(port: int) -> bool:
    return port == 53

def __extract_cname(record: dict, pro: Protocol) -> str:
    con_t = record.get("con_t", "-")

    if pro == Protocol.TCP and con_t == 8912:
        return record.get("c_tls_SNI", "-")
    if pro == Protocol.TCP and con_t == 1:
        return record.get("http_hostname", "-")

    if pro == Protocol.UDP and con_t == 27:
        return record.get("quic_SNI", "-")

    return record.get("fqdn", "-")


def __generate_id(record: dict) -> str:
    s_ip = record.get("s_ip", "-")
    c_ip = record.get("c_ip", "-")

    s_port = record.get("s_port", "-")
    c_port = record.get("c_port", "-")

    return f"{c_ip}:{c_port}-{s_ip}:{s_port}"


def __fetch_files(folder: str, prefix: str, suffix: str) -> list[str]:
    result = []
    for f in os.listdir(folder):
        if f.startswith(prefix) and f.endswith(suffix):
            result.append(os.path.join(folder, f))
    return sorted(result)



def __fetch_tests_files(path: str) -> list[tuple[str, str, str]]:
    data = []
    # Regular expressions for matching file names
    names = {
        'tcp': re.compile(r'log_tcp_complete$'), 
        'udp': re.compile(r'log_udp_complete$'),
        'bot': re.compile(r'log_bot_complete')
    }

    for root, _, files in os.walk(path):

        if os.path.basename(root).startswith("test"):
            logs = {}

            for f in files:
                full_path = os.path.join(root, f)
                for key, pattern in names.items():
                    if pattern.search(f):
                        logs[key] = full_path

            if len(logs) == 3:
                data.append((logs['bot'], logs['tcp'], logs['udp'], os.path.basename(root)))

    # sort by the numeric part of the folder name (e.g., test123 -> 123)
    sorted_data = sorted(data, key=lambda x: int(re.search(r'\d+', x[3]).group()))

    # return the relevant log file paths (bot, tcp, udp) without folder names
    return [(log[0], log[1], log[2]) for log in sorted_data]


def __extract_streaming_periods(path: str):

    frame = pandas.read_csv(path, sep=r"\s+")
    frame = frame[~frame["event"].str.contains("sniffer|browser|origin|net|app", case=False, na=False)]
    frame = frame.reset_index(drop=True)

    return [(frame.loc[i, "rel"], frame.loc[i + 1, "rel"]) for i in range(0, len(frame) - 1, 2)]

