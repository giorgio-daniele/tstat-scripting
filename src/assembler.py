import os
import re
import shutil
import pandas
import numpy
import statistics
import argparse

from lib.generic import LOG_BOT_COMPLETE
from lib.generic import LOG_HAR_COMPLETE
from lib.generic import LOG_TCP_PERIODIC
from lib.generic import LOG_UDP_PERIODIC

from lib.generic import Protocol

from lib.generic import __extract_streaming_periods


def statistics_values(rates: list):
    if not rates:                   # check if the list is empty
        return [float('nan')] * 5   # return NaN for all stats if no rates
 
    max_value = max(rates)                # calculate max
    min_value = min(rates)                # calculate min
    avg_value = sum(rates) / len(rates)   # calculate mean
    std_value = statistics.stdev(rates) if len(rates) > 1 else 0  # calculate std

    return [int(max_value), int(min_value), int(avg_value), int(std_value)]

def process_streaming_period(data: pandas.DataFrame, 
                               meta: pandas.DataFrame, ts: float, te: float, path: str, delta: float, num: int):
    
    intervals = range(ts, te, delta)

    records = []

    # loop over interval of delta, from ts to te
    for ti in intervals:
        tj = ti + delta 
        
        # extract all bins in the interval [ti; tj]
        bins = data[(data["ts"] <= tj) & (data["te"] >= ti)]
        if bins.empty:
            continue

        # extract all http in the interval [ti; tj]
        http = meta[(meta["ts"] >= ti) & (meta["ts"] <= tj)]

        # sort values and reset the index
        bins = bins.sort_values(by="ts")
        bins = bins.reset_index(drop=True)

        # sort values and reset the index
        http = http.sort_values(by="ts")
        http = http.reset_index(drop=True)

        # extract audio and video requests
        audio = http[http["mime"].str.contains("audio/mp4")]
        video = http[http["mime"].str.contains("video/mp4")]

        # count audio, video requests
        naudio, nvideo = len(audio), len(video)
        # count how many connections
        ncons = bins["id"].nunique()

        # calculate relative spans
        bins["rel_ts"] = numpy.maximum(bins["ts"], ti)
        bins["rel_te"] = numpy.minimum(bins["te"], tj)
        bins["rel_span"] = bins["rel_te"] - bins["rel_ts"]
        bins["abs_span"] = bins["te"] - bins["ts"]

        # rescale time span of intersecting bins
        ratio = bins["rel_span"] / bins["abs_span"].replace(0, 1)

        # get all bins in log_tcp_periodic
        tcp_bins = bins[bins["proto"] == Protocol.TCP]
        # get all bins in log_udp_periodic
        udp_bins = bins[bins["proto"] == Protocol.UDP]

        # compute stats for tcp
        c_tcp_packs = (tcp_bins["c_pkts_all"] * ratio).sum()  # total number of packets observed form the client (at layer 4)
        s_tcp_packs = (tcp_bins["s_pkts_all"] * ratio).sum()  # total number of packets observed form the server (at layer 4)
        c_tcp_bytes = (tcp_bins["c_bytes_all"] * ratio).sum() # client bytes transmitted in the payload, including retransmissions (TLS + HTTP)
        s_tcp_bytes = (tcp_bins["s_bytes_all"] * ratio).sum() # server bytes transmitted in the payload, including retransmissions (TLS + HTTP)

        # compute stats for udp
        c_udp_packs = (udp_bins["c_pkts_all"] * ratio).sum()    # total number of packets observed form the client (at layer 4)
        s_udp_packs = (udp_bins["s_pkts_all"] * ratio).sum()    # total number of packets observed form the server (at layer 4)
        c_udp_bytes = ((udp_bins["c_bytes_all"]) * ratio).sum() # client bytes transmitted in the payload (QUIC + TLS + HTTP)
        s_udp_bytes = ((udp_bins["s_bytes_all"]) * ratio).sum() # server bytes transmitted in the payload (QUIC + TLS + HTTP)

        # compute bin statistics
        bin_stats = statistics_values(bins["rel_span"].tolist())

        # init video and audio statistics
        video_stats, audio_stats = [0] * 4, [0] * 4

        # process video bitrates
        if not video.empty and "video_bitrate" in video.columns:
            video_rates = video["video_bitrate"].dropna().astype(int).tolist()
            if video_rates:
                video_stats = statistics_values(video_rates)
                    
        # process audio bitrates
        if not audio.empty and "audio_bitrate" in audio.columns:
            audio_rates = audio["audio_bitrate"].dropna().astype(int).tolist()
            if audio_rates:
                audio_stats = statistics_values(audio_rates)

        # generate the record for the current interval
        record = [
            ti, tj, len(bins), ncons,
            # tcp layer (client)
            int(c_tcp_packs), int(c_tcp_bytes),
            # udp layer (client)
            int(c_udp_packs), int(c_udp_bytes),
            # tcp layer (server)
            int(s_tcp_packs), int(s_tcp_bytes),
            # udp layer (server)
            int(s_udp_packs), int(s_udp_bytes),
            # bin statistics
            *bin_stats,
            # video bitrate stats
            *video_stats,
            #audio bitrate stats
            *audio_stats,
            # counts of video and audio requests
            nvideo, naudio]

        records.append(record)

    # define the columns for output dataframe
    columns = [
        "ts",               "te",               "nbins",            "ncons",
        "c_tcp_packs",      "c_tcp_bytes",      "c_udp_packs",      "c_udp_bytes",
        "s_tcp_packs",      "s_tcp_bytes",      "s_udp_packs",      "s_udp_bytes",
        "max_bins_span",    "min_bins_span",    "avg_bins_span",    "std_bins_span",
        "max_video_rate",   "min_video_rate",   "avg_video_rate",   "std_video_rate",
        "max_audio_rate",   "min_audio_rate",   "avg_audio_rate",   "std_audio_rate",
        "video_requests",   "audio_requests"
    ]

    # generate a frame
    metrics = pandas.DataFrame(records, columns=columns)
        
    # fix the timescale
    if not metrics.empty:
        first_ts = metrics["ts"].iloc[0]
        metrics["ts"] -= first_ts  # rescale ts
        metrics["te"] -= first_ts  # rescale te

    # save on disk
    return metrics
    #metrics.to_csv(os.path.join(path, f"log_stream_complete_{delta}-{num}"), index=False, sep=" ")
    # this is the end


def matches(cname, expressions):
    if isinstance(cname, str):
        return any(expression.search(cname) for expression in expressions)
    return False

if __name__ == "__main__":

    SERVERS = ["dazn", "sky"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)
    parser.add_argument("--server", required=True, choices=SERVERS)
    parser.add_argument("--step",   required=True)

    args = parser.parse_args()

    folder = args.folder
    server = args.server
    step   = args.step

    if server == "dazn":
        from lib.dazn import ROOT

    path = os.path.join(ROOT, "regexs", "linear.txt")
    with open(path) as f:
        strings = [line.strip() for line in f if line.strip()]
        regexps = [re.compile(string) for string in strings]

    tcp_data_path = os.path.join(folder, "data", "tcp", str(step))
    udp_data_path = os.path.join(folder, "data", "udp", str(step))
    mix_data_path = os.path.join(folder, "data", "mix", str(step))

    if os.path.exists(tcp_data_path):
        shutil.rmtree(tcp_data_path)
    if os.path.exists(udp_data_path):
        shutil.rmtree(udp_data_path)
    if os.path.exists(mix_data_path):
        shutil.rmtree(mix_data_path)

    os.makedirs(tcp_data_path)
    os.makedirs(udp_data_path)
    os.makedirs(mix_data_path)

    # load folder to be processed (e.g. test-1, test-2)
    folders = []
    for folder_name in os.listdir(folder):
        folder_path = os.path.join(folder, folder_name)
        if os.path.isdir(folder_path):
            if os.path.basename(folder_path).startswith("test"):
                folders.append(folder_path)
    folders.sort(key=os.path.basename)

    # init counters
    udp_count = 0
    tcp_count = 0
    mix_count = 0

    for folder in folders:

        print(f"Processing folder: {folder}")
        print(f"  - step: {step} ms, {int(step) / 1000} s")

        # load tstat tcp/udp periodics
        tper = pandas.read_csv(os.path.join(folder, LOG_TCP_PERIODIC), sep="\s+")
        uper = pandas.read_csv(os.path.join(folder, LOG_UDP_PERIODIC), sep="\s+")

        # load periods
        periods = __extract_streaming_periods(os.path.join(folder, LOG_BOT_COMPLETE))

        # filter multimedia flows (over TCP)
        medias_tcp = tper[tper["cname"].apply(lambda cname: matches(cname, regexps))].copy()
        # label
        medias_tcp["proto"] = Protocol.TCP

        # filter multimedia flows (over UDP)
        medias_udp = uper[uper["cname"].apply(lambda cname: matches(cname, regexps))].copy()
        # label
        medias_udp["proto"] = Protocol.UDP

        # loop over period
        for num, (ts, te) in enumerate(periods):

            # filter TCP bins within the period
            tcp_data = medias_tcp[(medias_tcp["ts"] <= float(te)) & (medias_tcp["te"] >= float(ts))]
            tot_tcp  = len(tcp_data["cname"])

            # filter UDP bins within the period
            udp_data = medias_udp[(medias_udp["ts"] <= float(te)) & (medias_udp["te"] >= float(ts))]
            tot_udp  = len(udp_data["cname"])

            # count how many bins are in total
            tot = tot_tcp + tot_udp

            tcp_per = 0
            udp_per = 0

            if tot > 0:
                tcp_per = (tot_tcp / tot) * 100
                udp_per = (tot_udp / tot) * 100

            print(f"  - period from [{ts}] to [{te}]")
            print(f"  - tot:     {tot}")
            print(f"  - tcp tot: {tot_tcp}")
            print(f"  - udp tot: {tot_udp}")
            print(f"  - tcp %:   {tcp_per:.2f}")
            print(f"  - udp %:   {udp_per:.2f}")
            print("_" * 40)

            data = pandas.concat([tcp_data, udp_data], ignore_index=True)  
            meta = pandas.read_csv(os.path.join(folder, LOG_HAR_COMPLETE), sep="\s+")

            if udp_per > 80:
                metrics = process_streaming_period(data=data, meta=meta, ts=ts, te=te, path=udp_data, delta=int(step), num=udp_count)
                metrics.to_csv(os.path.join(udp_data_path, f"sample_{step}-{udp_count}"), index=False, sep=" ")
                metrics.to_csv(os.path.join(mix_data_path, f"sample_{step}-{mix_count}"), index=False, sep=" ")
                udp_count +=1
                mix_count +=1
            else:
                metrics = process_streaming_period(data=data, meta=meta, ts=ts, te=te, path=tcp_data, delta=int(step), num=tcp_count)
                metrics.to_csv(os.path.join(tcp_data_path, f"sample_{step}-{tcp_count}"), index=False, sep=" ")
                metrics.to_csv(os.path.join(mix_data_path, f"sample_{step}-{mix_count}"), index=False, sep=" ")
                tcp_count +=1
                mix_count +=1
        print()
        



