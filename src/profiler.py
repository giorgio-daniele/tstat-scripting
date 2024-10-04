import os
import re
import pandas
import yaml
import numpy
import collections
import argparse

from lib.generic import __fetch_tests_files
from lib.generic import __extract_streaming_periods

def process_flows(tcp: pandas.DataFrame, udp: pandas.DataFrame, periods: list):
    f_tcp_cnames = collections.Counter()
    f_udp_cnames = collections.Counter()

    # loop over the periods
    for period in periods:
        s = period[0]
        e = period[1]

        # filter tcp and udp flows for the current period
        mask_tcp = (tcp["ts"].values <= e) & (tcp["te"].values >= s)
        lins_tcp: pandas.DataFrame = tcp[mask_tcp]

        mask_udp = (udp["ts"].values <= e) & (udp["te"].values >= s)
        lins_udp: pandas.DataFrame = udp[mask_udp]

        # update the counters for tcp and udp cname frequencies
        f_tcp_cnames.update((set(lins_tcp["cname"].values)))
        f_udp_cnames.update((set(lins_udp["cname"].values)))

    return f_tcp_cnames, f_udp_cnames

def counter_to_frame(frequencies: dict):
    frame = pandas.DataFrame(frequencies.items(), columns=["cname", "abs"])
    frame = frame.sort_values(by="abs", ascending=False).reset_index(drop=True)
    return frame

def load_statistics(path: str):

    # get the list of all entries in the directory
    entries = os.listdir(path)
    
    # filter out only the files (exclude directories)
    files = [f for f in entries if os.path.isfile(os.path.join(path, f))]
    
    # empty profile
    if len(files) == 0:
        return 0, 0, 0, None, None

    # read previous number of samples
    with open(os.path.join(path, "num_samples.txt"), 'r') as f:
        num = int(f.readline().strip())
    
    # read previous number of tcp analyzed flows
    with open(os.path.join(path, "num_tcp_flows.txt"), 'r') as f:
        num_tcp = int(f.readline().split(':')[-1].strip())

    # read previous number of udp analyzed flows
    with open(os.path.join(path, "num_udp_flows.txt"), 'r') as f:
        num_udp = int(f.readline().split(':')[-1].strip())

    # read previous tcp frequencies frame
    f_tcp_cnames = None
    if os.path.exists(os.path.join(path, "cnames_tcp.txt")):
        f_tcp_cnames = pandas.read_csv(os.path.join(path, "cnames_tcp.txt"), sep=" ")

    # read previous udp frequencies frame
    f_udp_cnames = None
    if os.path.exists(os.path.join(path, "cnames_udp.txt")):
        f_udp_cnames = pandas.read_csv(os.path.join(path, "cnames_udp.txt"), sep=" ")

    return num, num_tcp, num_udp, f_tcp_cnames, f_udp_cnames


if __name__ == "__main__":

    SERVERS = ["dazn", "sky"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)
    parser.add_argument("--server", required=True, choices=SERVERS)

    args = parser.parse_args()

    folder = args.folder
    server = args.server

    if server == "dazn":
        from lib.dazn import ROOT
        from lib.dazn import TELEMETRY_SERVICES

    # load existing data (if any)
    num, num_tcp, num_udp, f_tcp_cnames, f_udp_cnames = load_statistics(path=ROOT)

    # init counter
    csum_tcp_f = collections.Counter()
    csum_udp_f = collections.Counter()

    # load new data
    data = __fetch_tests_files(folder=folder)

    # samples counter to 0
    samples = 0

    # loop over all the tests
    for item in data:
        bot_file, tcp_file, udp_file = item

        print(f"Profiling test: {os.path.dirname(bot_file)}:")
        print(f"  - cap file: {bot_file}")
        print(f"  - tcp file: {tcp_file}")
        print(f"  - udp file: {udp_file}")
        print(f"  - out path: {ROOT}")
        print("-" * 40)

        # extract periods (streaming intervals)
        periods = __extract_streaming_periods(file=bot_file)

        # generate tcom
        tcom = pandas.read_csv(tcp_file, sep=" ")
        # generate ucom
        ucom = pandas.read_csv(udp_file, sep=" ")

        # remove telemetry cnames from tcp and udp flows
        tcom = tcom[~tcom["cname"].str.contains('|'.join(TELEMETRY_SERVICES), case=False, na=False)]
        ucom = ucom[~ucom["cname"].str.contains('|'.join(TELEMETRY_SERVICES), case=False, na=False)]

        # remove not known cnames from tcp and udp flows
        tcom = tcom[~tcom["cname"].eq("-")]
        ucom = ucom[~ucom["cname"].eq("-")]

        # process bot traces
        f_tcp, f_udp = process_flows(tcp=tcom, udp=ucom, periods=periods)

        # update number of samples
        samples = samples + len(periods)

        # update cumulative frequencies
        csum_tcp_f.update(f_tcp)
        csum_udp_f.update(f_udp)

    # update tcp flows analyzed
    tot_tcp = sum(csum_tcp_f.values()) + num_tcp
    tot_udp = sum(csum_udp_f.values()) + num_udp

    if f_tcp_cnames is not None:
        for cname, abs in f_tcp_cnames.itertuples(index=False):
            csum_tcp_f[cname] += abs

    if f_udp_cnames is not None:
        for cname, abs in f_udp_cnames.itertuples(index=False):
            csum_udp_f[cname] += abs

    # update the number of samples
    with open(os.path.join(ROOT, "num_samples.txt"), 'w') as f:
        f.write(str(num + samples))

    # update the number of tcp flows analyzed
    with open(os.path.join(ROOT, "num_tcp_flows.txt"), 'w') as f:
        f.write(str(tot_tcp))

    # update the number of udp flows analyzed
    with open(os.path.join(ROOT, "num_udp_flows.txt"), 'w') as f:
        f.write(str(tot_udp))

    # save cnames over tcp
    frame = counter_to_frame(frequencies=csum_tcp_f)
    frame.to_csv(os.path.join(ROOT, "cnames_tcp.txt"), index=False, sep=" ")

    # save cnames over udp
    frame = counter_to_frame(frequencies=csum_udp_f)
    frame.to_csv(os.path.join(ROOT, "cnames_udp.txt"), index=False, sep=" ")