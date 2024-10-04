import os
import re
import json
import urllib
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

from lib.generic import __fetch_files
from lib.generic import __private_address
from lib.generic import __reserved_address
from lib.generic import __is_dns_port
from lib.generic import __generate_id
from lib.generic import __extract_cname

from lib.dazn import DAZN_MANIFEST_DAZNEDGE
from lib.dazn import DAZN_MANIFEST_AWS_AKAMAI

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

    # define conditions to be applied to the frame
    a = frame["s_ip"].apply(__private_address)
    b = frame["s_ip"].apply(__reserved_address)
    c = frame["s_port"].apply(__is_dns_port)
    
    # apply filtering 
    frame = frame[~(a | b | c)]

    # add the id
    frame["id"] = frame.apply(__generate_id, axis=1)

    # add the cname
    if document in {Document.LOG_TCP_COMPLETE, Document.LOG_UDP_COMPLETE}:
        frame["cname"] = frame.apply(lambda record: __extract_cname(record=record, pro=protocol), axis=1)

    if document == Document.LOG_TCP_COMPLETE:
        frame["ts"] = frame["first"] - start
        frame["te"] = frame["last"]  - start

    if document == Document.LOG_UDP_COMPLETE:
        frame["ts"] = frame["s_first_abs"] - start
        frame["te"] = frame["ts"] + (frame["s_durat"] * 1000)

    if document == Document.LOG_TCP_PERIODIC:
        frame["ts"] = frame["time_abs_start"] - start
        frame["te"] = frame["ts"] + frame["bin_duration"]

    if document == Document.LOG_UDP_PERIODIC:
        frame["ts"] = frame["time_abs_start"] - start
        frame["te"] = frame["ts"] + frame["bin_duration"]
        
    return frame

def har_to_frame(start: float, har_file: str) -> pandas.DataFrame:
    records = []

    with open(har_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    entries  = data["log"]["entries"]
    rate_map = {
        "video": {**DAZN_MANIFEST_DAZNEDGE["video"], **DAZN_MANIFEST_AWS_AKAMAI["video"]},
        "audio": {**DAZN_MANIFEST_DAZNEDGE["audio"], **DAZN_MANIFEST_AWS_AKAMAI["audio"]}}

    for entry in entries:
        # compute timestamps
        ts = (datetime.datetime.strptime(entry["startedDateTime"], "%Y-%m-%dT%H:%M:%S.%fZ") - 
              datetime.datetime(1970, 1, 1)).total_seconds() * 1000 - float(start)

        # compute te
        te = ts + sum(max(0, entry["timings"].get(key, 0)) for key in ["blocked", "dns", "send", "wait", "receive", "ssl"])

        # get common values
        req: dict = entry.get("request", {})
        res: dict = entry.get("response", {})
        
        url:  str = req.get("url", "-")
        mime: str = res.get("content", {}).get("mimeType", "-")
        conn: str = entry.get("connection", "-")
        meth: str = req.get("method", "-")

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
    
        # append the record
        records.append([ts, te, meth, url, conn, mime, vrate, arate])
    columns = ["ts", "te", "method", "url", "connection", "mime", "video_bitrate", "audio_bitrate"]
    return pandas.DataFrame(records, columns=columns)

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

    # remove previous outputs
    for root, dirs, files in os.walk(folder):
        for dir in dirs:
            path = os.path.join(root, dir)
            if os.path.basename(path).startswith("test"):
                shutil.rmtree(path)

    for num, (cap_file, bot_file, har_file) in enumerate(zip(cap_files, bot_files, har_files)):
        cap_file_name = os.path.basename(cap_file)
        bot_file_name = os.path.basename(bot_file)
        har_file_name = os.path.basename(har_file)

        # generate the output path
        out = os.path.join(os.path.dirname(folder), f"test-{num + 1}")

        print(f"Processing files for test {num + 1}:")
        print(f"  - cap file: {cap_file_name}")
        print(f"  - bot file: {bot_file_name}")
        print(f"  - har file: {har_file_name}")
        print(f"  - out fold: {out}")
        print("-" * 40)

        # launch Tstat
        os.system(f"{TSTAT_BINARY} -G {TSTAT_GLOBAL} -T {TSTAT_CONFIG} {cap_file} -s {out} > /dev/null")

        # simplify Tstat output
        for root, dirs, files in os.walk(out):
            for dir in dirs:
                path = os.path.join(root, dir)
                for name in os.listdir(path):
                    shutil.move(os.path.join(path, name), out)
                shutil.rmtree(path)

        # experiment start timestamp
        start = 0

        # move bot trace to test folder
        bot_frame = pandas.read_csv(bot_file, sep=" ")
        start = bot_frame.iloc[0]["abs"]
        bot_frame.to_csv(os.path.join(out, LOG_BOT_COMPLETE), sep=" ", index=False)

        # move har trace to test folder
        har_frame = har_to_frame(start=start, har_file=har_file)
        har_frame.to_csv(os.path.join(out, LOG_HAR_COMPLETE), sep=" ", index=False)

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

        # save tstat traces
        tcom.to_csv(path_or_buf=os.path.join(out, LOG_TCP_COMPLETE), sep=" ", index=False)
        tper.to_csv(path_or_buf=os.path.join(out, LOG_TCP_PERIODIC), sep=" ", index=False)
        ucom.to_csv(path_or_buf=os.path.join(out, LOG_UDP_COMPLETE), sep=" ", index=False)
        uper.to_csv(path_or_buf=os.path.join(out, LOG_UDP_PERIODIC), sep=" ", index=False)
