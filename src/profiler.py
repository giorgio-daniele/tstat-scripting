import os
import re
import pandas
import yaml
import numpy
import collections
import argparse

from lib.generic import __fetch_tests_files
from lib.generic import __extract_streaming_periods

from lib.generic import LOG_BOT_COMPLETE
from lib.generic import LOG_HAR_COMPLETE
from lib.generic import LOG_NET_COMPLETE
from lib.generic import LOG_TCP_COMPLETE
from lib.generic import LOG_UDP_COMPLETE
from lib.generic import LOG_TCP_PERIODIC
from lib.generic import LOG_UDP_PERIODIC

def process_flows(tcom: pandas.DataFrame, ucom: pandas.DataFrame, ts: float, te: float,
                  tcp_counter: collections.Counter, 
                  udp_counter: collections.Counter):

    # Get the intersection of all TCP flows within the period
    data  = tcom[(tcom["ts"] <= te) & (tcom["te"] >= ts)]
    names = set(data["cname"]) 
    tcp_counter.update(names)

    # Get the intersection of all UDP flows within the period
    data = ucom[(ucom["ts"] <= te) & (ucom["te"] >= ts)]
    names = set(data["cname"]) 
    udp_counter.update(names)


def counter_to_frame(frequencies: dict):
    frame = pandas.DataFrame(frequencies.items(), columns=["cname", "abs"])
    frame = frame.sort_values(by="abs", ascending=False).reset_index(drop=True)
    return frame

def load_statistics(path: str):

    # Get all files
    files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    
    # No previous data
    if len(files) == 0:
        return {
            "num_events": None,
            "num_tcp_flows": None,
            "num_udp_flows": None,
            "cname_frequencies_tcp": None,
            "cname_frequencies_udp": None
        }
    
    # Read previous statistics about how many events have
    # been processed
    with open(os.path.join(path, "num_events"), "r") as f:
        num_evnts = int(f.readline().strip())
    
    # Read previous statistics about how many TCP flows have
    # been processed
    with open(os.path.join(path, "num_tcp_flows"), "r") as f:
        num_tcp_flows = int(f.readline().split(':')[-1].strip())

    # Read previous statistics about how many UDP flows have
    # been processed
    with open(os.path.join(path, "num_udp_flows"), "r") as f:
        num_udp_flows = int(f.readline().split(':')[-1].strip())

    # Read previous statistics about CNAMEs frequencies over
    # TCP flows
    cnames_frequencies_tcp = None
    if os.path.exists(os.path.join(path, "cnames_over_tcp")):
        cnames_frequencies_tcp = pandas.read_csv(os.path.join(path, "cnames_over_tcp"), sep=" ")

    # Read previous statistics about CNAMEs frequencies over
    # UDP flows
    cnames_frequencies_udp = None
    if os.path.exists(os.path.join(path, "cnames_over_udp")):
        cnames_frequencies_udp = pandas.read_csv(os.path.join(path, "cnames_over_udp"), sep=" ")

    return {
        "num_events": num_evnts,
        "num_tcp_flows": num_tcp_flows,
        "num_udp_flows": num_udp_flows,
        "cname_frequencies_tcp": cnames_frequencies_tcp,
        "cname_frequencies_udp": cnames_frequencies_udp
    }

def update_cname_frequncies(results: pandas.DataFrame | None, 
                            frequencies: collections.Counter, filename: str):
    
    if results is not None:
        old = results
        new = pandas.DataFrame(list(frequencies.items()), columns=["cname", "count"])
        frame = pandas.concat([old, new]).groupby("cname", as_index=False).sum()
    else:
        frame = pandas.DataFrame(list(frequencies.items()), columns=["cname", "count"])

    # Split the 'cname' into hostname, domain, and tld
    # frame[["hostname", "domain", "tld"]] = frame["cname"].str.split(r'\.', n=2, expand=True)

    # Save the frequencies to CSV
    frame.to_csv(os.path.join(METADATA, filename), sep=" ", index=False)

if __name__ == "__main__":

    SERVERS = ["dazn", "sky"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)
    parser.add_argument("--server", required=True, choices=SERVERS)

    args = parser.parse_args()

    folder = args.folder
    server = args.server

    if server == "dazn":
        from lib.dazn import METADATA
        from lib.dazn import TELEMETRY_SERVICES

    # Load previous statistics
    results = load_statistics(path=METADATA)

    # If they are all None, we init each one
    if all(result is None for result in results.values()):
        print(f"[WRN]: no previous profile detected for {server}")

    # Check if there is any tests folder in the provided folder
    if not os.path.exists(os.path.join(folder, "tests")):
        print(f"[ERR]: no [tests] folder detected in {folder}")
        exit(1)

    # Init counters
    cnames_tcp_frequencies = collections.Counter()
    cnames_udp_frequencies = collections.Counter()

    # Init number of events processed
    events = 0

    for test in os.listdir(os.path.join(folder, "tests")):

        # Extract the streaming periods
        periods = __extract_streaming_periods(path=os.path.join(folder, "tests", test, LOG_BOT_COMPLETE))

        # Update number of events
        events += len(periods)

        # Generate TCP complete frame
        tcom = pandas.read_csv(os.path.join(folder, "tests", test, LOG_TCP_COMPLETE), sep=" ")
        # Generate UDP complete frame
        ucom = pandas.read_csv(os.path.join(folder, "tests", test, LOG_UDP_COMPLETE), sep=" ")

        # Remove telemetry cnames from tcp and udp flows
        tcom = tcom[~tcom["cname"].str.contains('|'.join(TELEMETRY_SERVICES), case=False, na=False)]
        ucom = ucom[~ucom["cname"].str.contains('|'.join(TELEMETRY_SERVICES), case=False, na=False)]

        # Remove not known cnames from TCP and UDP flows
        tcom = tcom[~tcom["cname"].eq("-")]
        ucom = ucom[~ucom["cname"].eq("-")]

        for period in periods:
            ts = period[0]
            te = period[1]

            # Get statistics about this period
            process_flows(tcom=tcom, 
                          ucom=ucom, ts=ts, te=te, 
                          tcp_counter=cnames_tcp_frequencies,
                          udp_counter=cnames_udp_frequencies)

    # Update and save CNAME frequencies for TCP
    update_cname_frequncies(results["cname_frequencies_tcp"], 
                            cnames_tcp_frequencies, "cnames_over_tcp")

    # Update and save CNAME frequencies for UDP
    update_cname_frequncies(results["cname_frequencies_udp"], 
                            cnames_udp_frequencies, "cnames_over_udp")

    results["num_events"] = (results["num_events"] or 0) + events
    results["num_tcp_flows"] = (results["num_tcp_flows"] or 0) + sum(cnames_tcp_frequencies.values())
    results["num_udp_flows"] = (results["num_udp_flows"] or 0) + sum(cnames_udp_frequencies.values())
    
    # Update the number of periods analyzed
    with open(os.path.join(METADATA, "num_events"), "w") as f:
        f.write(str(results["num_events"]))

    # Update the number of TCP flows anaylyzed
    with open(os.path.join(METADATA, "num_tcp_flows"), "w") as f:
        f.write(str(results["num_tcp_flows"]))

    # Update the number of UDP flows anaylyzed
    with open(os.path.join(METADATA, "num_udp_flows"), "w") as f:
        f.write(str(results["num_udp_flows"]))
    
    print(f"[MSG]: {os.path.join(folder, 'tests')} have been processed:")
    print(f"  - TCP flows analyzed (incremental): {results['num_tcp_flows']}")
    print(f"  - UDP flows analyzed (incremental): {results['num_udp_flows']}")
    print(f"  - BOT evnts analyzed (incremental): {results['num_events']}")