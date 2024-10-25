import os
import shutil
import pandas
import shutil
import argparse

def merge_data(s_file: str, l_file: str):

    s_frame = pandas.read_csv(s_file, sep=" ")
    l_frame = pandas.read_csv(l_file, sep=" ")

    records = []
    
    # Remove periods in which avg_video_rate is zero
    l_frame = l_frame[l_frame["avg_video_rate"] > 0]
    
    for _, rec in l_frame.iterrows():
        ts = rec["ts"]
        te = rec["te"]

        # Filter s_df rows within the [ts, te] range
        samples = s_frame[(s_frame["ts"] >= ts) & (s_frame["te"] <= te)]

        # Remove ground truth from samples
        samples = samples.drop("avg_video_rate", axis=1)
        
        # Remove not necessary columns
        samples = samples.drop("ts", axis=1)
        samples = samples.drop("te", axis=1)

        if not samples.empty:
            # Flatten matching rows into a single row
            rows = samples.values.flatten()

            # Create new column names for the matching rows
            cols = [f"{col}_#{i}" for i in range(1, len(samples) + 1) for col in samples.columns]

            # Combine rec with flattened matching rows
            record = pandas.DataFrame([rec.tolist() + rows.tolist()], columns=list(l_frame.columns) + cols)

            # Append the combined row to the final records
            records.append(record)

    if records:
        data = pandas.concat(records, ignore_index=True)
        data = data.drop("ts", axis=1)
        data = data.drop("te", axis=1)
    else:
        data = pandas.DataFrame()
    return data


if __name__ == "__main__":

    HIGH_FREQ, LOW_FREQ = "1000", "10000"

    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)
    parser.add_argument("--protocol", required=True, choices=["tcp", "udp"])
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    # Define media folder paths
    high_freq_samples = os.path.join(args.folder, "media", args.protocol, HIGH_FREQ)
    low_freq_samples  = os.path.join(args.folder, "media", args.protocol, LOW_FREQ)

    # Get the files
    s_files = sorted([os.path.join(high_freq_samples, f) for f in os.listdir(high_freq_samples)])
    l_files = sorted([os.path.join(low_freq_samples,  f) for f in os.listdir(low_freq_samples)])

    if os.path.exists(args.output):
        shutil.rmtree(args.output)
    os.mkdir(args.output)

    offset = 0

    for num, (s, l) in enumerate(zip(s_files, l_files)):

        print(f"[MSG]: processing {args.folder}")

        frame = merge_data(s_file=s, l_file=l)
        frame.to_csv(os.path.join(args.output, f"sample-{num + int(offset)}"), sep=" ", index=False)
        print(f"  - saving: {os.path.join(args.output, f'sample-{num + int(offset)}')}")
    print()
