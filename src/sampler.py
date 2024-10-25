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
        return [float('nan')] * 4   # return NaN for all stats if no rates
 
    max_value = max(rates)                # calculate max
    min_value = min(rates)                # calculate min
    avg_value = sum(rates) / len(rates)   # calculate mean
    std_value = statistics.stdev(rates) if len(rates) > 1 else 0  # calculate std

    return [float(max_value), float(min_value), float(avg_value), float(std_value)]

def calculate_statistics(http: pandas.DataFrame, mime_type: str, bitrate_column: str):
    frame = http[http["mime"].str.contains(mime_type)]
    if not frame.empty and bitrate_column in frame.columns:
        rates = frame[bitrate_column].dropna().astype(int).tolist()
        if rates:
            return statistics_values(rates)
    return [0] * 4

def merge_intervals(intervals: list[list[float]]) -> list[list[float]]:
    intervals.sort(key=lambda x: x[0])
    result = []
    for interval in intervals:
        if not result or interval[0] > result[-1][1]:
            result.append(interval)
        else:
            result[-1][1] = max(result[-1][1], interval[1])
    return result
    
def process_period(data: pandas.DataFrame, 
                   meta: pandas.DataFrame, ts: float, te: float, delta: float, proto: Protocol | None):
    
        rows = []

        for ti in numpy.arange(ts, te, delta):
            tj = ti + delta 
            
            # get bins and http requests in the floaterval [ti; tj]
            samples  = data[(data["ts"] <= tj) & (data["te"] >= ti)].copy()
            dialogue = meta[(meta["ts"] >= ti) & (meta["ts"] <= tj)].copy()

            if samples.empty:
                #record_length = 27 if proto == Protocol.TCP else 18
                #rows.append([ti, tj, 0, 0] + ([0] * record_length))
                rows.append([ti, tj, float(0), float(0)])
                continue
            
            # count how many connections are in there, count how many requests
            # for audio, video and the manifes the client performed
            connections = len(set(samples["id"]))
            video_requests = len(dialogue[dialogue["mime"].str.contains("video/mp4")])
            audio_requests = len(dialogue[dialogue["mime"].str.contains("audio/mp4")])
            media_requests = len(dialogue[dialogue["mime"].str.contains("dash")])

            # reset timestamp associated to each sample
            samples["rel_ts"] = numpy.maximum(samples["ts"], ti)
            samples["rel_te"] = numpy.maximum(samples["ts"], tj)
            samples["rel_te"] = numpy.minimum(samples["te"], tj)
            samples["rel_span"] = samples["rel_te"] - samples["rel_ts"]
            samples["abs_span"] = samples["te"] - samples["ts"]

            # collect intervals to merge later
            intervals = samples[["rel_ts", "rel_te"]].values.tolist()

            # calculate total span of merged intervals
            total_merged_span = sum(end - start for start, end in merge_intervals(intervals))

            # calculate idle time
            idle_time = delta - total_merged_span

            # compute the covering index for each sample
            cover = samples["rel_span"] / samples["abs_span"].replace(0, 1)
            
            # generate statistics about sample lasting, video and audio quality
            samples_spans_stats = statistics_values(samples["rel_span"].tolist())
            video_quality_stats = calculate_statistics(dialogue, "video/mp4", "video_rate")
            audio_quality_stats = calculate_statistics(dialogue, "audio/mp4", "audio_rate")

            # common metrics for TCP, UDP, or other protocols
            c_packs_all = float((samples["c_pkts_all"] * cover).sum())  
            s_packs_all = float((samples["s_pkts_all"] * cover).sum())  
            c_bytes_all = float((samples["c_bytes_all"] * cover).sum())  
            s_bytes_all = float((samples["s_bytes_all"] * cover).sum())

            if proto == Protocol.TCP:
                c_ack_cnt = float((samples["c_ack_cnt"] * cover).sum())  
                s_ack_cnt = float((samples["s_ack_cnt"] * cover).sum())
                c_ack_cnt_p = float((samples["c_ack_cnt_p"] * cover).sum())  
                s_ack_cnt_p = float((samples["s_ack_cnt_p"] * cover).sum())  
                c_bytes_uniq = float((samples["c_bytes_uniq"] * cover).sum())  
                s_bytes_uniq = float((samples["s_bytes_uniq"] * cover).sum()) 
                c_packs_retx = float((samples["c_pkts_retx"] * cover).sum()) 
                s_packs_retx = float((samples["s_pkts_retx"] * cover).sum()) 
                c_packs_data = float((samples["c_pkts_data"] * cover).sum()) 
                s_packs_data = float((samples["s_pkts_data"] * cover).sum()) 
                
                rows.append([
                    ti, 
                    tj, 
                    # idle_time, 
                    # len(samples), 
                    # connections, 
                    # c_packs_all, 
                    # c_ack_cnt, 
                    # c_ack_cnt_p, 
                    # c_bytes_all, 
                    # c_bytes_uniq,
                    # s_packs_all, 
                    # s_ack_cnt, 
                    # s_ack_cnt_p, 
                    s_bytes_all, 
                    # s_bytes_uniq,
                    # c_packs_retx, 
                    # s_packs_retx, 
                    # c_packs_data, 
                    # s_packs_data,
                    # samples_spans_stats[0], 
                    # samples_spans_stats[1],
                    # samples_spans_stats[2],
                    # samples_spans_stats[3],
                    # video_quality_stats[0], 
                    # video_quality_stats[1],
                    video_quality_stats[2],
                    # video_quality_stats[3],
                    # audio_quality_stats[0],
                    # audio_quality_stats[1],
                    # audio_quality_stats[2],
                    # audio_quality_stats[3],
                    # video_requests, 
                    # audio_requests, 
                    # media_requests
                    ])

            if proto == Protocol.UDP:
                rows.append([
                    ti, 
                    tj, 
                    # idle_time, 
                    # len(samples), 
                    # connections, 
                    # c_packs_all, 
                    # c_bytes_all, 
                    # s_packs_all, 
                    s_bytes_all,
                    # samples_spans_stats[0], 
                    # samples_spans_stats[1],
                    # samples_spans_stats[2],
                    # samples_spans_stats[3],
                    # video_quality_stats[0], 
                    # video_quality_stats[1],
                    video_quality_stats[2],
                    # video_quality_stats[3],
                    # audio_quality_stats[0],
                    # audio_quality_stats[1],
                    # audio_quality_stats[2],
                    # audio_quality_stats[3],
                    # video_requests, 
                    # audio_requests, 
                    # media_requests
                    ])

        # # define column names based on protocol
        if proto == Protocol.TCP:
            columns = [
                "ts", 
                "te", 
                # "idle", 
                # "nbins", 
                # "ncons", 
                # "c_pkts_all", 
                # "c_ack_cnt", 
                # "c_ack_cnt_p", 
                # "c_bytes_all", 
                # "c_bytes_uniq",
                # "s_pkts_all", 
                # "s_ack_cnt", 
                # "s_ack_cnt_p", 
                "s_bytes_all", 
                # "s_bytes_uniq",
                # "c_pkts_retx", 
                # "s_pkts_retx", 
                # "c_pkts_data", 
                # "s_pkts_data",
                # "max_bin_duration", 
                # "min_bin_duration", 
                # "avg_bin_duration", 
                # "std_bin_duration",
                # "max_video_rate", 
                # "min_video_rate", 
                "avg_video_rate", 
                # "std_video_rate",
                # "max_audio_rate", 
                # "min_audio_rate", 
                # "avg_audio_rate", 
                # "std_audio_rate", 
                # "video_reqs", 
                # "audio_reqs", 
                # "media_reqs"
                ]
            
        if proto == Protocol.UDP:
            columns = [
                "ts", 
                "te", 
                # "idle", 
                # "nbins", 
                # "ncons", 
                # "c_pkts_all", 
                # "c_bytes_all", 
                # "s_pkts_all", 
                "s_bytes_all",
                # "max_bin_duration", 
                # "min_bin_duration", 
                # "avg_bin_duration", 
                # "std_bin_duration",
                # "max_video_rate", 
                # "min_video_rate", 
                "avg_video_rate", 
                # "std_video_rate",
                # "max_audio_rate", 
                # "min_audio_rate", 
                # "avg_audio_rate", 
                # "std_audio_rate",
                # "video_reqs", 
                # "audio_reqs", 
                # "media_reqs"
                ]
            
        # generate and rescale the DataFrame
        metrics = pandas.DataFrame(rows, columns=columns)

        if not metrics.empty:
            first_ts = metrics["ts"].iloc[0]
            metrics["ts"] -= first_ts
            metrics["te"] -= first_ts
            
        #print(metrics)
        return metrics

def matches(cname, expressions):
    if isinstance(cname, str):
        return any(expression.search(cname) for expression in expressions)
    return False

def load_regex_patterns(path: str):
    with open(path) as f:
        strings = [line.strip() for line in f if line.strip()]
    return [re.compile(string) for string in strings]

def create_dirs(paths: list[str]):
    for path in paths:
        if os.path.exists(path):
            shutil.rmtree(path)
        os.makedirs(path)

def load_tests(folder: str):
    folders = []
    for folder_name in os.listdir(folder):
        folder_path = os.path.join(folder, folder_name)
        if os.path.isdir(folder_path):
            if os.path.basename(folder_path).startswith("test"):
                folders.append(folder_path)
    folders.sort(key=os.path.basename)
    return folders

if __name__ == "__main__":

    SERVERS = ["dazn", "sky"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)
    parser.add_argument("--server", required=True, choices=SERVERS)
    parser.add_argument("--step",   required=True)

    args = parser.parse_args()

    # get the arguments
    folder = args.folder
    server = args.server
    step   = args.step

    # select the provider
    if server == "dazn":
        from lib.dazn import ROOT

    # path of all folders
    outputs = [
        os.path.join(folder, "media", "tcp", str(step)),    #1
        os.path.join(folder, "media", "udp", str(step)),    #2
        os.path.join(folder, "media", "mix", str(step)),    #3

        os.path.join(folder, "noise", "tcp", str(step)),    #4
        os.path.join(folder, "noise", "udp", str(step)),    #5
        os.path.join(folder, "noise", "mix", str(step)),    #6

    ]
    
    # create directory for the output
    create_dirs(paths=outputs)

    # load all compiled test from Tstat
    folders = load_tests(folder=folder)

    # init counters
    medias_over_tcp = 0
    medias_over_udp = 0
    medias_over_mix = 0
    noises_over_tcp = 0
    noises_over_udp = 0
    noises_over_mix = 0

    for folder in folders:
        print(f"Processing folder: {folder}")
        print(f"  - step: {step} ms, {float(step) / 1000} s")

        # load regular expressions
        path = os.path.join(ROOT, "regexs", "linear.txt")
        regs = load_regex_patterns(path=path)

        # load periods
        path = os.path.join(folder, LOG_BOT_COMPLETE)
        periods = __extract_streaming_periods(path=path)

        # generate tcp periodic frame
        path = os.path.join(folder, LOG_TCP_PERIODIC)
        tper = pandas.read_csv(path, sep="\s+")
        tper["proto"] = Protocol.TCP

        # generate udp periodic frame
        path = os.path.join(folder, LOG_UDP_PERIODIC)
        uper = pandas.read_csv(path, sep="\s+")
        uper["proto"] = Protocol.UDP

        # filter all media flows over TCP
        media_tcp_bins = tper[tper["cname"].apply(lambda cname: matches(cname, regs))]
        # filter all noise flows over TCP
        noise_tcp_bins = tper[~tper["cname"].apply(lambda cname: matches(cname, regs))]

        # filter all noise flows over UDP
        media_udp_bins = uper[uper["cname"].apply(lambda cname: matches(cname, regs))]
        # filter all noise flows over UDP
        noise_udp_bins = uper[~uper["cname"].apply(lambda cname: matches(cname, regs))]

        for num, (ts, te) in enumerate(periods):

            # filter all TCP bins from media subset
            # and count how many bins are in there
            tcp_bins = media_tcp_bins[
                (media_tcp_bins["ts"] <= float(te)) & 
                (media_tcp_bins["te"] >= float(ts))]
            tot_tcp = len(tcp_bins["cname"])

            # filter all UDP bins from media subset
            # and count how many bins are in there
            udp_bins = media_udp_bins[
                (media_udp_bins["ts"] <= float(te)) & 
                (media_udp_bins["te"] >= float(ts))]
            tot_udp = len(udp_bins["cname"])

            # init percentage
            tcp_per = 0
            udp_per = 0

            tot = tot_tcp + tot_udp

            if tot > 0:
                tcp_per = (tot_tcp / tot) * 100
                udp_per = (tot_udp / tot) * 100

            # a streaming over tcp
            if tcp_per >= 90:
                metrics = process_period(data=tcp_bins, 
                                         meta=pandas.read_csv(os.path.join(folder, LOG_HAR_COMPLETE), sep="\s+"), 
                                         ts=ts, 
                                         te=te, 
                                         delta=float(step), proto=Protocol.TCP)
                metrics.to_csv(os.path.join(outputs[0], f"log_tcp_media_{medias_over_tcp}"), index=False, sep=" ")
                medias_over_tcp += 1
                #print(f"  - period processed over TCP"

            # a streaming over udp
            elif udp_per >= 90:
                metrics = process_period(data=udp_bins, 
                                         meta=pandas.read_csv(os.path.join(folder, LOG_HAR_COMPLETE), sep="\s+"), 
                                         ts=ts, 
                                         te=te, 
                                         delta=float(step), proto=Protocol.UDP)
                metrics.to_csv(os.path.join(outputs[1], f"log_udp_media_{medias_over_udp}"), index=False, sep=" ")
                medias_over_udp += 1
                #print(f"  - period processed over UDP")

            # a streaming over mix
            # else:
            #     metrics = process_period(data=pandas.concat([tcp_bins, udp_bins], ignore_index=True), 
            #                              meta=pandas.read_csv(os.path.join(folder, LOG_HAR_COMPLETE), sep="\s+"), 
            #                              ts=ts, 
            #                              te=te, 
            #                              delta=float(step), proto=Protocol.UDP)
            #     metrics.to_csv(os.path.join(outputs[2], f"log_mix_media_{medias_over_mix}"), index=False, sep=" ")
            #     medias_over_mix += 1
            #     print(f"  - period processed over MIX")

            # # filter all TCP bins from media subset
            # # and count how many bins are in there
            # tcp_bins = noise_tcp_bins[
            #     (noise_tcp_bins["ts"] <= float(te)) & 
            #     (noise_tcp_bins["te"] >= float(ts))]

            # # filter all UDP bins from media subset
            # # and count how many bins are in there
            # udp_bins = noise_udp_bins[
            #     (noise_udp_bins["ts"] <= float(te)) & 
            #     (noise_udp_bins["te"] >= float(ts))]
            
            # if tcp_per >= 90:
            #     metrics = process_period(data=tcp_bins, 
            #                              meta=pandas.read_csv(os.path.join(folder, LOG_HAR_COMPLETE), sep="\s+"), 
            #                              ts=ts, 
            #                              te=te, 
            #                              delta=float(step), proto=Protocol.TCP)
            #     metrics.to_csv(os.path.join(outputs[3], f"log_tcp_noise_{noises_over_tcp}"), index=False, sep=" ")
            #     noises_over_tcp += 1
            # elif udp_per >= 90:
            #     metrics = process_period(data=udp_bins, 
            #                              meta=pandas.read_csv(os.path.join(folder, LOG_HAR_COMPLETE), sep="\s+"), 
            #                              ts=ts, 
            #                              te=te, 
            #                              delta=float(step), proto=Protocol.UDP)
            #     metrics.to_csv(os.path.join(outputs[4], f"log_udp_noise_{noises_over_udp}"), index=False, sep=" ")
            #     noises_over_udp += 1
            # else:
            #     metrics = process_period(data=pandas.concat([tcp_bins, udp_bins], ignore_index=True), 
            #                              meta=pandas.read_csv(os.path.join(folder, LOG_HAR_COMPLETE), sep="\s+"), 
            #                              ts=ts, 
            #                              te=te, 
            #                              delta=float(step), proto=Protocol.UDP)
            #     metrics.to_csv(os.path.join(outputs[2], f"log_mix_media_{medias_over_mix}"), index=False, sep=" ")
            #     medias_over_mix += 1   
        #print(f"  - all periods have been processed")
        #print()



