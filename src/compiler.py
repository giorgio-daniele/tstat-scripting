"""
compiler.py

Description:
    This script serves as a wrapper for TStat, compiling all output related to streambot-based experiments. 
    It processes the following types of files:
    - PCAP files, which capture the network traffic generated during the experiments.
    - HTTP Archive (HAR) files, which contain a record of all requests and responses logged by the bot.
    
    The resulting compiled data provides a comprehensive overview of the experiment's network interactions.

Usage:
    This script can be run from the command line with appropriate arguments to specify the input files and 
    the desired output format.
"""


import os
import re
import json
import shutil
import pandas
import datetime
import argparse

from lib.generic import LOG_BOT_COMPLETE
from lib.generic import LOG_HAR_COMPLETE
from lib.generic import LOG_NET_COMPLETE
from lib.generic import LOG_TCP_COMPLETE
from lib.generic import LOG_UDP_COMPLETE
from lib.generic import LOG_TCP_PERIODIC
from lib.generic import LOG_UDP_PERIODIC

from lib.generic import LOG_AUDIO_COMPLETE
from lib.generic import LOG_VIDEO_COMPLETE

from lib.generic import __fetch_files
from lib.generic import __private_address
from lib.generic import __reserved_address
from lib.generic import __is_dns_port
from lib.generic import __generate_id
from lib.generic import __extract_cname

from lib.dazn import DAZN_MANIFEST_VERSION_A
from lib.dazn import DAZN_MANIFEST_VERSION_B

from lib.generic import CAP
from lib.generic import HAR
from lib.generic import BOT

from lib.generic import TSTAT_BINARY
from lib.generic import TSTAT_CONFIG
from lib.generic import TSTAT_GLOBAL

from lib.generic import Document
from lib.generic import Protocol

def process_trace(document: Document, 
                  protocol: Protocol, start: float, path: str) -> pandas.DataFrame:

    frame = pandas.read_csv(path, sep=r'\s+')
    frame.columns = [re.sub(r'[#:0-9]', '', col) for col in frame.columns]

    # Remove any LAN communication, any multicast communication and evenually any DNS traffic
    # that has been captured at UDP level
    frame = frame[~(frame["s_ip"].apply(__private_address)  | 
                    frame["s_ip"].apply(__reserved_address) | 
                    frame["s_port"].apply(__is_dns_port))]

    # Assign to each flow a unique ID by means of the source IP, the destination IP, the source
    # port number and the destination port number
    frame["id"] = frame.apply(__generate_id, axis=1)

    # Extract the canonical name of the server the client is talking to. The procedure goes this:
    # if a TLS-based flow, the canonical name is fetched from the TLS ClientHello; if a raw
    # HTTP flow, the canonical name is extracted from the Host field in the request/response;
    # otherwise, the canonical name is fetched from DNS traffic
    if document in {Document.LOG_TCP_COMPLETE, Document.LOG_UDP_COMPLETE}:
        frame["cname"] = frame.apply(lambda record: __extract_cname(record=record, pro=protocol), axis=1)

    # Define the new origins
    if document == Document.LOG_TCP_COMPLETE:
        frame["ts"] = frame["first"] - start
        frame["te"] = frame["last"]  - start

    if document == Document.LOG_UDP_COMPLETE:
        frame["ts"] = frame["s_first_abs"] - start
        frame["te"] = frame["ts"] + (frame["s_durat"] * 1000)

    if document in {Document.LOG_TCP_PERIODIC, Document.LOG_UDP_PERIODIC}:
        frame["ts"] = frame["time_abs_start"] - start
        frame["te"] = frame["ts"] + frame["bin_duration"]

    return frame

def archive_to_frame(start: float, har_file: str) -> pandas.DataFrame:
    records = []

    with open(har_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    entries  = data["log"]["entries"]
    rate_map = {
        "video": {**DAZN_MANIFEST_VERSION_A["video"], **DAZN_MANIFEST_VERSION_B["video"]},
        "audio": {**DAZN_MANIFEST_VERSION_A["audio"], **DAZN_MANIFEST_VERSION_B["audio"]} }
    
    audio_records = []
    video_records = []

    for entry in entries:

        # Compute ts (when the request has been issued)
        ts = (datetime.datetime.strptime(entry["startedDateTime"], "%Y-%m-%dT%H:%M:%S.%fZ") - 
              datetime.datetime(1970, 1, 1)).total_seconds() * 1000 - float(start)

        # Compute te (when the request has been completed)
        te = ts + sum(max(0, entry["timings"].get(k, 0)) 
                      for k in ["blocked", "dns", "send", "wait", "receive", "ssl"])

        # get common values
        req: dict = entry.get("request", {})
        res: dict = entry.get("response", {})
        
        url:  str = req.get("url", "-")
        mime: str = res.get("content", {}).get("mimeType", "-")
        conn: str = entry.get("connection", "-")
        meth: str = req.get("method", "-")
        size: str = res.get("content", {}).get("size", "-")

        vrate: str = "-"
        arate: str = "-"
        
        for key in rate_map["video"]:
            if key in url:
                vrate = str(rate_map["video"][key]["bitrate"])
                mime = "video/mp4"
                break

        for key in rate_map["audio"]:
            if key in url:
                arate = str(rate_map["audio"][key]["bitrate"])
                mime = "audio/mp4"
                break

        exts = [".mp4", ".cmfv", ".cmfa", ".mpd"]
        for ext in exts:
            if ext in url:
                url = url.split(ext)[0] + ext
                break
        else:
            url = url[:70]

        # Save record in video frame
        if mime == "video/mp4":
            video_records.append([ts, te, meth, url, conn, mime, vrate, size])
        # Save record in audio frame
        if mime == "audio/mp4":
            audio_records.append([ts, te, meth, url, conn, mime, arate, size])
        # Save record in complete frame
        records.append([ts, te, meth, url, conn, mime, vrate, arate, size])

    com  = pandas.DataFrame(records, 
                            columns=["ts", "te", "method", "url", "connection", "mime", "video_rate", "audio_rate", "size"])
    vcom = pandas.DataFrame(video_records, 
                            columns=["ts", "te", "method", "url", "connection", "mime", "rate", "size"])
    acom = pandas.DataFrame(audio_records, 
                            columns=["ts", "te", "method", "url", "connection", "mime", "rate", "size"])

    return (com, vcom, acom)

if __name__ == "__main__":

    SERVERS = ["dazn", "sky"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)
    parser.add_argument("--server", required=True, choices=SERVERS)

    args = parser.parse_args()

    folder = args.folder
    server = args.server

    cap_files = __fetch_files(folder=folder, prefix=LOG_NET_COMPLETE, suffix=CAP)
    bot_files = __fetch_files(folder=folder, prefix=LOG_BOT_COMPLETE, suffix=BOT)
    har_files = __fetch_files(folder=folder, prefix=LOG_HAR_COMPLETE, suffix=HAR)

    # Remove previous outputs
    for root, dirs, files in os.walk(os.path.join(folder, "..")):
        for dir in dirs:
            path = os.path.join(root, dir)
            if os.path.basename(path).startswith("test"):
                shutil.rmtree(path)

    root = os.path.join(os.path.dirname(folder), "tests")
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)

    for num, (cap_file, bot_file, har_file) in enumerate(zip(cap_files, bot_files, har_files)):
        cap_file_name = os.path.basename(cap_file)
        bot_file_name = os.path.basename(bot_file)
        har_file_name = os.path.basename(har_file)

        # Generate the output path
        out = os.path.join(os.path.dirname(folder), "tests", f"test-{num + 1}")

        print(f"[MSG]: processing files for test {num + 1}:")
        print(f"  - cap file: {cap_file_name}")
        print(f"  - bot file: {bot_file_name}")
        print(f"  - har file: {har_file_name}")
        print(f"  - out fold: {out}")
        print("-" * 40)

        # Launch Tstat
        os.system(f"{TSTAT_BINARY} -G {TSTAT_GLOBAL} -T {TSTAT_CONFIG} {cap_file} -s {out} > /dev/null")

        # Simplify Tstat output
        for root, dirs, files in os.walk(out):
            for dir in dirs:
                path = os.path.join(root, dir)
                for name in os.listdir(path):
                    shutil.move(os.path.join(path, name), out)
                shutil.rmtree(path)

        # Experiment start timestamp
        start = 0

        # Move bot trace to test folder
        bot_frame = pandas.read_csv(bot_file, sep=" ")
        start = bot_frame.iloc[0]["abs"]
        bot_frame.to_csv(os.path.join(out, LOG_BOT_COMPLETE), sep=" ", index=False)

        # Move har trace to test folder
        com, video, audio = archive_to_frame(start=start, har_file=har_file)

        tcom = process_trace(start=start, 
                             document=Document.LOG_TCP_COMPLETE, 
                             protocol=Protocol.TCP, path=os.path.join(out, LOG_TCP_COMPLETE))
        ucom = process_trace(start=start, 
                             document=Document.LOG_UDP_COMPLETE, 
                             protocol=Protocol.UDP, path=os.path.join(out, LOG_UDP_COMPLETE))

        tper = process_trace(start=start, 
                             document=Document.LOG_TCP_PERIODIC, 
                             protocol=Protocol.TCP, path=os.path.join(out, LOG_TCP_PERIODIC))
        uper = process_trace(start=start, 
                             document=Document.LOG_UDP_PERIODIC, 
                             protocol=Protocol.UDP, path=os.path.join(out, LOG_UDP_PERIODIC))
        
        tper = tper.merge(tcom[["id", "cname"]], on="id", how="left")
        uper = uper.merge(ucom[["id", "cname"]], on="id", how="left")

        # Save har complete
        com.to_csv(os.path.join(out, LOG_HAR_COMPLETE), sep=" ", index=False)

        # Save video complete
        video.to_csv(os.path.join(out, LOG_VIDEO_COMPLETE), sep=" ", index=False)

        # Save audio complete
        audio.to_csv(os.path.join(out, LOG_AUDIO_COMPLETE), sep=" ", index=False)

        # Save tstat complete and periodic
        tcom.to_csv(path_or_buf=os.path.join(out, LOG_TCP_COMPLETE), sep=" ", index=False)
        tper.to_csv(path_or_buf=os.path.join(out, LOG_TCP_PERIODIC), sep=" ", index=False)
        ucom.to_csv(path_or_buf=os.path.join(out, LOG_UDP_COMPLETE), sep=" ", index=False)
        uper.to_csv(path_or_buf=os.path.join(out, LOG_UDP_PERIODIC), sep=" ", index=False)
