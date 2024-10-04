# """
#     File: main.py
#     Description: this script acts as a wrapper around Tstat for compiling
#                  experiments performed with Streambot.

#     Usage: 
#         python main.py --path=<directory_path> --provider=<provider_name>

#     Arguments:
#         --path: the directory path containing HAR files.
#         --provider: the name of the provider (e.g., dazn) to categorize the data.

#     author:  Giorgio Daniele
#     date:    2024-09-01

#     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#     IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#     AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# """

import os
import re
import enum
import yaml
import json
import pandas
import time
import numpy
import ipaddress
import argparse
import datetime
import numpy

# # from collections import Counter

# DAZN_STREAMING = r'dc[a-z]|live|livedazn'
# SKIE_STREAMING = r'^linear.*\.skycdp\.com$'
# CONV_TELEMETRY = r'.*conviva\.com$'

# def find_files(path: str, pre: str, suf: str) -> list[str]:
#     return sorted([os.path.join(path, f) 
#                 for f in os.listdir(path) 
#                         if f.startswith(pre) and f.endswith(suf)])

# def none_files(n: int) -> list[str]:
#     return [None for _ in range(0, n)]


# def __check_priv(ip: str) -> bool:
#     try:
#         return ipaddress.ip_address(ip).is_private
#     except ValueError:
#         return False


# def __check_mcst(ip: str) -> bool:
#     try:
#         return ipaddress.ip_address(ip).is_multicast
#     except ValueError:
#         return False


# def __check_dnss(port: int) -> bool:
#     return port == 53


# LOG_TCP_COMPLETE = "log_tcp_complete"
# LOG_TCP_PERIODIC = "log_tcp_periodic"
# LOG_UDP_COMPLETE = "log_udp_complete"
# LOG_UDP_PERIODIC = "log_udp_periodic"

# def fmt_tstamp(tstamp: float):
#     return f"{tstamp // 1000:.2f}s {tstamp % 1000:.2f}ms"

# class Document(enum.Enum):
#     LOG_TCP_COMPLETE = 1
#     LOG_TCP_PERIODIC = 2
#     LOG_UDP_COMPLETE = 3
#     LOG_UDP_PERIODIC = 4

# class Protocol(enum.Enum):
#     TCP = 1
#     UDP = 2


# def process_frame(basis: float, 
#                       doc: Document, 
#                       pro: Protocol, path: str) -> pandas.DataFrame:
    
#     # get the frame
#     frame: pandas.DataFrame = pandas.read_csv(path, sep='\s+')

#     # remove any digit from original tstat documents
#     frame.columns = [re.sub(r'[#:0-9]', '', col) for col in frame.columns]

#     # remove any local, multicast and dns flow: we do not 
#     # care about them
#     frame = frame[~(
#         frame.apply(lambda r: __check_priv(r["s_ip"]),   axis=1) |
#         frame.apply(lambda r: __check_mcst(r["s_ip"]),   axis=1) |
#         frame.apply(lambda r: __check_dnss(r["s_port"]), axis=1)
#     )]
 
#     def __get_cname(record: dict):
#         con_t = record.get("con_t", "-")

#         if pro == Protocol.TCP and con_t == 8912:
#             return record.get("c_tls_SNI", "-")
#         if pro == Protocol.TCP and con_t == 1:
#             return record.get("http_hostname", "-")
        
#         if pro == Protocol.UDP and con_t == 27:
#             return record.get("quic_SNI", "-")

#         return record.get("fqdn", "-")
    
#     def __get_token(record: dict):
#         cname = record.get("cname", "-")

#         if not cname or cname == "-":
#             return "unknown"
        
#         if prov == "dazn" and re.match(DAZN_STREAMING, cname):
#             return "dazn-streaming.net"
        
#         if prov == "sky" and re.match(SKIE_STREAMING, cname):
#             return "sky-streaming.net"
        
#         if re.match(CONV_TELEMETRY, cname):
#             return "conviva-telemetry.net"
        
#         return re.sub(r'\d', '', cname)

#     def __get_alias(record: dict):
#         s_ip = record.get("s_ip", "-")
#         c_ip = record.get("c_ip", "-")

#         s_port = record.get("s_port", "-")
#         c_port = record.get("c_port", "-")

#         return f"{c_ip}:{c_port}-{s_ip}:{s_port}"

#     # generate an alias by which easily target a flow
#     frame["alias"] = frame.apply(__get_alias, axis=1)

#     if doc == Document.LOG_TCP_COMPLETE or doc == Document.LOG_UDP_COMPLETE:
#         # add the server canonical name
#         frame["cname"] = frame.apply(__get_cname, axis=1)
#         # add the server token
#         frame["token"] = frame.apply(__get_token, axis=1)

#     if pro == Protocol.TCP and doc == Document.LOG_TCP_COMPLETE:
#         frame["ts"] = frame["first"] - float(basis)
#         frame["te"] = frame["last"]  - float(basis)

#     # when processing a tcp flow, beacuse of protocol feature, we know
#     # when the flow has started and finished exactly; however, when
#     # facing udp flows, we are not able anymore to associate a flow
#     # to client-server and server-client; therefore, we only focus on
#     # the server-client side

#     if pro == Protocol.UDP and doc == Document.LOG_UDP_COMPLETE:
#         frame["ts"] = frame["s_first_abs"] - float(basis)
#         frame["te"] = frame["ts"] + (frame["s_durat"] * 1000)

#     if doc == Document.LOG_TCP_PERIODIC or doc == Document.LOG_UDP_PERIODIC:
#         frame["ts"] = frame["time_abs_start"] - float(basis)
#         frame["te"] = frame["ts"] + frame["bin_duration"]

#     frame = frame.sort_values(by=["alias", "ts"])

#     # generate cumulative statistics on bytes the server 
#     # has sent
#     if doc == Document.LOG_TCP_PERIODIC:
#         frame[f"csum_s_bytes"] = frame.groupby("alias")["s_bytes_uniq"].cumsum()
#     if doc == Document.LOG_UDP_PERIODIC:
#         frame[f"csum_s_bytes"] = frame.groupby("alias")["s_bytes_all"].cumsum()

#     return frame

# # def get_resolution(mpd_dict: dict, qos, mmt: str):
# #     if mmt in mpd_dict and qos in mpd_dict[mmt]:
# #         return mpd_dict[mmt][qos]["band"]
# #     return None

# def process_har(file: str, basis: float):

#     primary_mpd = {
#         "video": {
#             "video_288kbps": {
#                 "band":   288,
#                 "width":  480,
#                 "height": 270,
#                 "rate":   25,
#             },
#             "video_480kbps": {
#                 "band":   480,
#                 "width":  640,
#                 "height": 360,
#                 "rate":   25,
#             },
#             "video_840kbps": {
#                 "band":  840,
#                 "width": 640,
#                 "height": 960,
#                 "rate":  25,
#             },
#             "video_1500kbps": {
#                 "band":   1500,
#                 "width":  960,
#                 "height": 540,
#                 "rate":   25,
#             },
#             "video_2300kbps": {
#                 "band":   2300,
#                 "width":  1280,
#                 "height": 720,
#                 "rate":   25,
#             },
#             "video_3000kbps": {
#                 "band":   3000,
#                 "width":  1280,
#                 "height": 720,
#                 "rate":   25,
#             },
#             "video_4400kbps": {
#                 "band":   4400,
#                 "width":  1280,
#                 "height": 720,
#                 "rate":   50,
#             },
#             "video_6500kbps": {
#                 "band":   6500,
#                 "width":  1280,
#                 "height": 720,
#                 "rate":   50,
#             },
#             "video_8000kbps": {
#                 "band":   8000,
#                 "width":  1920,
#                 "height": 1080,
#                 "rate":   50,
#             },
#         },
#         "audio": {
#             "audio_64kbps": {
#                 "rate": 48,
#                 "band": 64
#             },
#             "audio_128kbps": {
#                 "rate": 48,
#                 "band": 128
#             }
#         }
#     }

#     secondary_mpd = {
#         "video": {
#             "stream_video_1": {
#                 "band":  8000,
#                 "width": 1280,
#                 "height": 720,
#                 "rate":  50
#             },
#             "stream_video_2": {
#                 "band":  6500,
#                 "width": 1280,
#                 "height": 720,
#                 "rate":  50
#             },
#             "stream_video_3": {
#                 "band":  4400,
#                 "width": 1280,
#                 "height": 720,
#                 "rate":  50
#             },
#             "stream_video_4": {
#                 "band":  3000,
#                 "width": 1280,
#                 "height": 720,
#                 "rate":  25
#             },
#             "stream_video_5": {
#                 "band":  2300,
#                 "width": 1280,
#                 "height": 720,
#                 "rate":  25
#             },
#             "stream_video_6": {
#                 "band":  1500,
#                 "width": 960,
#                 "height": 540,
#                 "rate":  25
#             },
#             "stream_video_7": {
#                 "band":  840,
#                 "width": 960,
#                 "height": 540,
#                 "rate":  25
#             },
#             "stream_video_8": {
#                 "band":  480,
#                 "width": 960,
#                 "height": 540,
#                 "rate":  25
#             },
#             "stream_video_9": {
#                 "band":  288,
#                 "width": 480,
#                 "height": 270,
#                 "rate":  25
#             },
#         },
#         "audio": {
#             "stream_audio_10_": {
#                 "rate": 48,
#                 "band": 65_604
#             },
#             "stream_audio_11_": {
#                 "rate": 48,
#                 "band": 128_058
#             },
#             "stream_audio_12_": {
#                 "rate": 48,
#                 "band": 128
#             }
#         }
#     }

#     records = []

#     with open(file, 'r', encoding='utf-8') as f:
#         data = f.read()

#     data = json.loads(data)

#     for entry in data["log"]["entries"]:

#         # compute ts
#         ts = entry["startedDateTime"]
#         utc = datetime.datetime.strptime(entry["startedDateTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
#         ts = (utc - datetime.datetime(1970, 1, 1)).total_seconds() * 1000
#         ts = ts - float(basis)

#         # compute te
#         te = ts + sum(max(0, entry["timings"][key]) 
#                    for key in ["blocked", "dns", "send", "wait", "receive", "ssl"])
        
#         # patterns for dazn edge, akamai, amazon cloud front
#         daznedge = re.compile(r'dc[a-z]-[a-zA-Z0-9_-]+-livedazn\.daznedge\.net')
#         akamaize = re.compile(r'dc[a-z]-[a-zA-Z0-9_-]+-livedazn\.akamaized\.net')
#         amazoncf = re.compile(r'dc[a-z]-[a-zA-Z0-9_-]+-live.cdn\.indazn\.com')
        
#         # get the url
#         url = entry.get("request", {}).get("url", "")[:140]
#         # get the method
#         mtd = entry.get("request", {}).get("method", "")
#         # get the http version
#         vrs = entry.get("response", {}).get("httpVersion", "")
#         # get the mime type
#         mmt = entry.get("response", {}).get("content", {}).get("mimeType", "")
#         # get the content size
#         sze = entry.get("response", {}).get("content", {}).get("size", 0)
#         # get the server ip address
#         s_ip = entry.get("serverIPAddress", "")

#         video_band  = "-"
#         audio_band  = "-"

#         # check if the http request is for video/audio
#         # on daznedge or akamai
#         if daznedge.search(url) or akamaize.search(url) or amazoncf.search(url):

#             for key in primary_mpd["video"].keys():
#                 if key in url:
#                     #print(f"video request at {url}")
#                     video_band = primary_mpd["video"][key]["band"]
#                     mmt = "video/mp4"
#                     break
#             for key in secondary_mpd["video"].keys():
#                 if key in url:
#                     #print(f"video request at {url}")
#                     video_band = secondary_mpd["video"][key]["band"]
#                     mmt = "video/mp4"
#                     break

#             for key in primary_mpd["audio"].keys():
#                 if key in url:
#                     #print(f"audio request at {url}")
#                     audio_band = primary_mpd["audio"][key]["band"]
#                     mmt = "audio/mp4"
#                     break
#             for key in secondary_mpd["audio"].keys():
#                 if key in url:
#                     #print(f"audio request at {url}")
#                     audio_band = secondary_mpd["audio"][key]["band"]
#                     mmt = "audio/mp4"
#                     break

#         # append a new line
#         records.append([ts, te, mtd, url, vrs, mmt, sze, s_ip, video_band, audio_band])
    
#     heads = ["ts", "te", "method", "url", "version", "mime_type", "content_size", "s_ip", "video_band", "audio_band"]
#     frame = pandas.DataFrame(records, columns=heads)

#     return frame

# def __volume_metrics(rec: dict) -> dict:
#     try:
#         num = rec.get("relte", 0) - rec.get("relts", 0)
#         den = rec.get("te", 0)    - rec.get("ts", 0) or 1

#         # if tcp, we can compute how many packets the
#         # protocol has carried with upper layer data
#         # and how many packets the protocol has carried
#         # with no upper layer data (just acknowledgement)
#         # or handshake


#         result = { 
#             "s_bytes_l4":  rec.get("s_bytes_all",  None),
#             "c_bytes_l4":  rec.get("c_bytes_all",  None),
#             "s_bytes_l7":  rec.get("s_bytes_uniq", None),
#             "c_bytes_l7":  rec.get("c_bytes_uniq", None),
#             "s_packs_l4":  rec.get("s_pkts_all",   None),
#             "c_packs_l4":  rec.get("c_pkts_all",   None),
#             "s_packs_l7":  rec.get("s_pkts_data",  None),
#             "c_packs_l7":  rec.get("c_pkts_data",  None),
#         }

#         # Only compute for values present and not NaN
#         for key in result:
#             if result[key] is not None and not numpy.isnan(result[key]):
#                 result[key] = int(float(num) / den * result[key])
#             else:
#                 result[key] = numpy.nan
#         return result

#     except (TypeError, ValueError, ZeroDivisionError) as e:
#         print(f"Error occurred: {e}")
#         return None
    
# def volume_metrics(rec: dict) -> int:
#     return __volume_metrics(rec)

# def extract_numbers(s):
#     return [int(num) for num in re.findall(r'\d+', s)]

def process_streams(data: pandas.DataFrame, 
                    http: pandas.DataFrame, periods: list, out: str, delta=5_000):
    
    # loop over all streamings, and collect all interesting
    # metrics; these metrics are supposed to be used as way
    # for classifing non-supervised streaming samples

    def statistics_values(values: list):
        # filter out invalid values (e.g., NaN)
        values = [v for v in values if v is not None and not numpy.isnan(v)]
        
        if not values:
            return ["-"] * 4
        
        return [
            int(numpy.max(values)),
            int(numpy.min(values)),
            int(numpy.mean(values)),
            int(numpy.std(values))
        ]

    for num, (ts, te, name) in enumerate(periods):
        
        # print(fmt_tstamp(ts))
        # print(fmt_tstamp(te))
        # print(name)

        idex = num + 1

        # generate a list of records
        records = []

        ti = ts
        tj = ti + delta

        while ti < te:

            # filter all bins that intersect the current interval [ti; tj]
            bins: pandas.DataFrame = data[numpy.maximum(data["ts"], ti) <= numpy.minimum(data["te"], tj)]
            bins: pandas.DataFrame = bins.sort_values(by="ts")
            bins: pandas.DataFrame = bins.reset_index(drop=True)

            if bins.empty:
                ti = ti + delta
                tj = tj + delta
                continue

            # filter all http requests the client has issued within [ti; tj]
            reqs: pandas.DataFrame = http[(http["ts"] >= ti) & (http["ts"] <= tj)]
            reqs: pandas.DataFrame = reqs.sort_values(by="ts")
            reqs: pandas.DataFrame = reqs.reset_index(drop=True)

            mdash = reqs[reqs['url'].str.contains('.mpd', na=False)]            # filter mpeg/dash requests
            audio = reqs[reqs["mime_type"].str.contains("audio/mp4", na=False)] # filter audio/mp4 requests
            video = reqs[reqs["mime_type"].str.contains("video/mp4", na=False)] # filter video/mp4 requests


            # get the number of connections
            ncons = len(set(bins["alias"]))
            # get the number of the bins
            nbins = len(bins)
            
            bins["spans"] = bins["te"] - bins["ts"]                 # compute the duration of each bin
            bins["relts"] = bins["ts"].apply(lambda x: max(x, ti))  # define the new ts, according to the intersection
            bins["relte"] = bins["te"].apply(lambda x: min(x, tj))  # define the new te, according to the intersection
            bins["relspans"] = bins["relte"] - bins["relts"]        # compute the duration of each new truncated bin

            def safe_int(value):
                return int(value) if value != "-" else value
            
            client_tcp_segments = 0          # how many tcp segments have been observed from client to server
            server_tcp_segments = 0          # how many tcp segments have been observed from server to client
            client_tcp_segments_bytes = 0    # how many bytes have been observed at layer 4, when using tcp, from client to server
            server_tcp_segments_bytes = 0    # how many bytes have been observed at layer 4, when using tcp, from server to client

            client_udp_datagrams = 0         # how many udp datagrams have been observed from client to server
            server_udp_datagrams = 0         # how many udp datagrams have been observed from server to client
            client_udp_datagrams_bytes = 0   # how many bytes have been observed at layer 4, when using udp, from client to server
            server_udp_datagrams_bytes = 0   # how many bytes have been observed at layer 4, when using udp, from server to client

            client_data_packs = 0  # how many http messages have been observed from client to server
            server_data_packs = 0  # how many http messages have been observed from server to client
            client_data_bytes = 0  # how many bytes have been observed at layer 7 from client to server          
            server_data_bytes = 0  # how many bytes have been observed at layer 7 from server to client
            
            client_trasportation_bytes = 0    # how many bytes have been observed from client to server, at layer 4
            server_trasportation_bytes = 0    # how many bytes have been observed from server to client, at layer 4

            client_trasportation_packs = 0  # how many packets have been observed from client to server, at layer 4
            server_trasportation_packs = 0  # how many packets have been observed from server to client, at layer 4

            client_cumulative_data_bytes = 0
            server_cumulative_data_bytes = 0
            client_cumulative_trasportation_bytes = 0
            server_cumulative_trasportation_bytes = 0

            tcp_bin_cnt = 0
            udp_bin_cnt = 0

            # compute metrics associated to each bin
            for num, bin in bins.iterrows():
                    
                    num = bin["relspans"]    # get the duration in the current interval
                    den = bin["spans"]       # get the real duration

                    if den == 0:
                        den = 1

                    rto = float(num / den)   # compute covering index
                    
                    if bin["proto"] == Protocol.TCP:
                        
                        # update tcp bin counter
                        tcp_bin_cnt += 1

                        # compute how many tcp segments
                        client_tcp_segments += (bin["c_pkts_all"] * rto)
                        server_tcp_segments += (bin["s_pkts_all"] * rto)

                        # compute how many tcp bytes
                        client_tcp_segments_bytes += (bin["c_bytes_all"] * rto)
                        server_tcp_segments_bytes += (bin["s_bytes_all"] * rto)

                        # compute how many data packets
                        client_data_packs += (bin["c_pkts_data"] * rto)
                        server_data_packs += (bin["s_pkts_data"] * rto)

                        # compute how many data bytes
                        client_data_bytes += (bin["c_bytes_uniq"] * rto)
                        server_data_bytes += (bin["s_bytes_uniq"] * rto)

                        # update trasportation packs (generic counter)
                        client_trasportation_packs += (bin["c_pkts_all"] * rto)
                        server_trasportation_packs += (bin["s_pkts_all"] * rto)

                        # update trasportation bytes (generic counter)
                        client_trasportation_bytes += (bin["c_bytes_all"] * rto)
                        server_trasportation_bytes += (bin["s_bytes_all"] * rto)
                        
                    if bin["proto"] == Protocol.UDP:

                        # update tcp bin counter
                        udp_bin_cnt += 1

                        # compute how many udp datagrams
                        client_udp_datagrams += (bin["c_pkts_all"] * rto)
                        server_udp_datagrams += (bin["s_pkts_all"] * rto)

                        # compute how many udp bytes
                        client_udp_datagrams_bytes += ((bin["c_bytes_all"] + 8) * rto)
                        server_udp_datagrams_bytes += ((bin["s_bytes_all"] + 8) * rto)

                        # compute how many data packets
                        client_data_packs += (bin["c_pkts_all"] * rto)
                        server_data_packs += (bin["c_pkts_all"] * rto)

                        # compute how many data bytes
                        client_data_bytes += (bin["c_bytes_all"] * rto)
                        server_data_bytes += (bin["s_bytes_all"] * rto)

                        # update trasportation packs (generic counter)
                        client_trasportation_packs += (bin["c_pkts_all"] * rto)
                        server_trasportation_packs += (bin["s_pkts_all"] * rto)

                        # update trasportation bytes (generic counter)
                        client_trasportation_bytes += ((bin["c_bytes_all"] + 8) * rto)
                        server_trasportation_bytes += ((bin["s_bytes_all"] + 8) * rto)
                    
            # update cumulative statistics
            client_cumulative_data_bytes += client_data_bytes
            server_cumulative_data_bytes += server_data_bytes
            client_cumulative_trasportation_bytes += client_trasportation_bytes
            server_cumulative_trasportation_bytes += server_trasportation_bytes

            bin_stats = statistics_values(bins['spans'])

            if not video.empty and "video_band" in video.columns:
                video_band_list = video["video_band"].dropna().tolist()  # remove NaN values
                video_stats = statistics_values(video_band_list)
            else:
                video_stats = ["-", "-", "-", "-"]

            if not audio.empty and "audio_band" in audio.columns:
                audio_band_list = audio["audio_band"].dropna().tolist()  # remove NaN values
                audio_stats = statistics_values(audio_band_list)
            else:
                audio_stats = ["-", "-", "-", "-"]


            # generate the record
            record = [
                ti, tj, 
                nbins, tcp_bin_cnt, udp_bin_cnt,
                ncons,

                ############# client side 

                # layer tcp
                safe_int(client_tcp_segments),
                safe_int(client_tcp_segments_bytes),
                # layer udp
                safe_int(client_udp_datagrams),
                safe_int(client_udp_datagrams_bytes),
                # ovearall tcp/udp
                safe_int(client_trasportation_packs),
                safe_int(client_trasportation_bytes),
                # cumulative
                safe_int(client_cumulative_trasportation_bytes),
                # upper layer
                safe_int(client_data_packs),
                safe_int(client_data_bytes),
                # cumulative
                safe_int(client_cumulative_data_bytes),


                ############# server side 

                # layer tcp
                safe_int(server_tcp_segments),
                safe_int(server_tcp_segments_bytes),
                # layer udp
                safe_int(server_udp_datagrams),
                safe_int(server_udp_datagrams_bytes),
                # ovearall tcp/udp
                safe_int(server_trasportation_packs),
                safe_int(server_trasportation_bytes),
                # cumulative
                safe_int(server_cumulative_trasportation_bytes),
                # upper layer
                safe_int(server_data_packs),
                safe_int(server_data_bytes),
                # cumulative
                safe_int(server_cumulative_data_bytes),

                bin_stats[0], 
                bin_stats[1], 
                bin_stats[2], 
                bin_stats[3],
                video_stats[0], video_stats[1], video_stats[2], video_stats[3],
                audio_stats[0], audio_stats[1], audio_stats[2], audio_stats[3]
            ]

            # add the record
            records.append(record)
        
            # update interval
            ti = ti + delta
            tj = tj + delta
        
        columns = [
            "ts", "te", 
            "nbins", "tcp_bins_count", "udp_bins_count",
            "ncons",

            # client side
            "c_tcp_segments",
            "c_tcp_segments_bytes",
            "c_udp_datagrams",
            "c_udp_datagrams_bytes",
            "c_trasportation_packs",
            "c_trasportation_bytes",
            "c_cumulative_trasportation_bytes",
            "c_data_packs",
            "c_data_bytes",
            "c_cumulative_data_bytes",

            # server side
            "s_tcp_segments",
            "s_tcp_segments_bytes",
            "s_udp_datagrams",
            "s_udp_datagrams_bytes",
            "s_trasportation_packs",
            "s_trasportation_bytes",
            "s_cumulative_trasportation_bytes",
            "s_data_packs",
            "s_data_bytes",
            "s_cumulative_data_bytes",

            # bin stats
            "max_bins_span", "min_bins_span", "avg_bins_span", "std_bins_span",

            # video stats
            "max_video_res", "min_video_res", "avg_video_res", "std_video_res",

            # audio stats
            "max_audio_res", "min_audio_res", "avg_audio_res", "std_audio_res"]
        
        
        # generate a frame
        metrics = pandas.DataFrame(records, columns=columns)
        # save on disk
        metrics.to_csv(os.path.join(out, f"log_dash_complete-{idex}"), index=False, sep=" ")

# if __name__ == "__main__":

#     try:
#         with open("settings.yaml", "r") as file:
#             sets = yaml.safe_load(file)
#     except FileNotFoundError:
#         exit(1)
#     except Exception as e:
#         exit(1)

#     # parse the command line arguments
#     parser = argparse.ArgumentParser(description="Generate Tstat files.")
#     parser.add_argument('--path', required=True)
#     parser.add_argument('--provider', required=True,  choices=['sky', 'dazn'])
#     parser.add_argument('--delta', required=False, type=int)
#     args = parser.parse_args()

#     # get the arguments
#     path = args.path
#     prov = args.provider
#     delta = args.delta

#     # get configs for tstat
#     bin = sets["binary"]
#     glb = sets["global"]
#     cnf = sets["config"]

#     cap_files = find_files(path=path, pre="log_net_complete", suf="pcap")
#     bot_files = find_files(path=path, pre="log_bot_complete", suf="csv")
#     har_files = find_files(path=path, pre="log_har_complete", suf="har")

#     if len(bot_files) == 0:
#         bot_files = none_files(len(cap_files))

#     if len(har_files) == 0:
#         har_files = none_files(len(cap_files))

#     ##################### start of cap file processing

#     for num, (cap_file, bot_file, har_file) in enumerate(zip(cap_files, bot_files, har_files)):

#         cap_file_name = os.path.basename(cap_file)
#         bot_file_name = os.path.basename(bot_file)
#         har_file_name = os.path.basename(har_file)

#         msg = f"""processing...
#         wireshark trace: {cap_file_name}
#         streambot trace: {bot_file_name}
#         weblogger trace: {har_file_name} at {os.path.dirname(path)}
#         """

#         # generate a directory to host experimental data
#         out = os.path.join(os.path.dirname(path), f"test-{num + 1}")

#         # remove previous experimental data
#         os.system(f"rm -rf {out}")

#         # launch tstat
#         os.system(f"{bin} -G {glb} -T {cnf} {cap_file} -s {out} > /dev/null")

#         # clean-up output directory
#         os.system(f"mv {out}/*/* {out}/ && rm -rf {out}/*/")

#         bot_com = None
#         bot_clk = None
#         har_com = None

#         periods = []

#         # generate a frame for streambot trace and
#         # get the timestamp when the test has began,
#         # therfore each tstat timestamp will be
#         # shifted according to a new origin

#         if bot_file is not None:
#             bot_com = pandas.read_csv(bot_file, sep=r"\s+")
#             bot_clk = bot_com.iloc[0]["abs"]
#             stmings = bot_com[~bot_com["event"].str.contains("sniffer|browser|origin|net|app", case=False, na=False)]
#             stmings = stmings.reset_index(drop=True)
            
#             # sava a copy in the experiment folder
#             name, _ = bot_file_name.replace(".csv", "").split("-")
#             os.system(f"cp {bot_file} {os.path.join(out, name)}")

#             # get the list of all streaming periods
#             periods = [(stmings.loc[i, "rel"], stmings.loc[i + 1, "rel"], stmings.loc[i, "event"]) 
#                        for i in range(0, len(stmings) - 1, 2)]

#         # generate a frame from weblogger trace and
#         # generate a simplfied version of all https
#         # requests the client did while performing
#         # the experiment

#         if har_file is not None:
#             har_com = process_har(file=har_file, basis=bot_clk)
#             # sava a copy in the experiment folder
#             name, _ = har_file_name.replace(".har", "").split("-")
#             har_com.to_csv(os.path.join(out, name), sep=" ", index=False)
        
#         ######################### TCP
                            
#         tcom = None
#         tper = None

#         # log tcp complete processing
#         tcom = process_frame(basis=bot_clk, 
#                                  doc=Document.LOG_TCP_COMPLETE,
#                                  pro=Protocol.TCP, path=os.path.join(out, LOG_TCP_COMPLETE))
        
#         # log tcp periodic processing
#         tper = process_frame(basis=bot_clk, 
#                                  doc=Document.LOG_TCP_PERIODIC,
#                                  pro=Protocol.TCP, path=os.path.join(out, LOG_TCP_PERIODIC))
        
#         # merge the frames
#         tper = tper.merge(tcom[["alias", "token", "cname"]], on="alias", how="left")

#         # save the frames
#         tcom.to_csv(path_or_buf=os.path.join(out, LOG_TCP_COMPLETE), sep=" ", index=False)
#         tper.to_csv(path_or_buf=os.path.join(out, LOG_TCP_PERIODIC), sep=" ", index=False)

#         ######################### UDP

#         ucom = None
#         uper = None

#         # log udp complete processing
#         ucom = process_frame(basis=bot_clk, 
#                              doc=Document.LOG_UDP_COMPLETE,
#                              pro=Protocol.UDP, path=os.path.join(out, LOG_UDP_COMPLETE))
        
#         # log udp periodic processing
#         uper = process_frame(basis=bot_clk, 
#                              doc=Document.LOG_UDP_PERIODIC,
#                              pro=Protocol.UDP, path=os.path.join(out, LOG_UDP_PERIODIC))

#         # merge the frames
#         uper = uper.merge(ucom[["alias", "token", "cname"]], on="alias", how="left")

#         # save the frames
#         ucom.to_csv(path_or_buf=os.path.join(out, LOG_UDP_COMPLETE), sep=" ", index=False)
#         uper.to_csv(path_or_buf=os.path.join(out, LOG_UDP_PERIODIC), sep=" ", index=False)

#         # remove anything that is not a streaming (generate a brand new frame)
#         tcp = tper[tper["token"] == "dazn-streaming.net"]
#         tcp["proto"] = Protocol.TCP
                    
#         # remove anything that is not a streaming (generate a brand new frame)
#         udp = uper[uper["token"] == "dazn-streaming.net"]
#         udp["proto"] = Protocol.UDP

#         # combine tcp and udp flows in one single frame
#         dat_com = pandas.concat([tcp, udp], ignore_index=True)
#         dat_com = dat_com.sort_values(by="ts")
#         dat_com = dat_com.reset_index(drop=True)

#         #process each stream
#         process_streams(data=dat_com, 
#                         http=har_com, periods=periods, out=out, delta=delta)        # remove anything that is not a streaming (generate a brand new frame)
#         tcp = tper[tper["token"] == "dazn-streaming.net"]
#         tcp["proto"] = Protocol.TCP
                    
#         # remove anything that is not a streaming (generate a brand new frame)
#         udp = uper[uper["token"] == "dazn-streaming.net"]
#         udp["proto"] = Protocol.UDP

#         # combine tcp and udp flows in one single frame
#         dat_com = pandas.concat([tcp, udp], ignore_index=True)
#         dat_com = dat_com.sort_values(by="ts")
#         dat_com = dat_com.reset_index(drop=True)

#         #process each stream
#         process_streams(data=dat_com, 
#                         http=har_com, periods=periods, out=out, delta=delta)