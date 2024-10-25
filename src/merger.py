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

    S_SAMPLING = "1000"
    L_SAMPLING = "10000"

    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)
    parser.add_argument("--protocol", required=True, choices=["tcp", "udp"])
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    # define media folder paths
    s_samples = os.path.join(args.folder, "media", args.protocol, S_SAMPLING)
    l_samples = os.path.join(args.folder, "media", args.protocol, L_SAMPLING)

    # get the files
    s_files = sorted([os.path.join(s_samples, f) for f in os.listdir(s_samples)])
    l_files = sorted([os.path.join(l_samples, f) for f in os.listdir(l_samples)])

    if os.path.exists(args.output):
        shutil.rmtree(args.output)
    os.mkdir(args.output)
    offset = 0

    for num, (s, l) in enumerate(zip(s_files, l_files)):

        print(f"Processing folder: {args.folder}")
        print(f"  - merging: {s} and {l}")
        
        frame = merge_data(s_file=s, l_file=l)
        frame.to_csv(os.path.join(args.output, f"sample-{num + int(offset)}"), sep=" ", index=False)
        print(f"  - saving: {os.path.join(args.output, f'sample-{num + int(offset)}')}")
    print()


    # for num, (f1, f2) in enumerate(zip(long_files, fast_files)):

    #     print(f"Processing folder: {path}")
    #     print(f"  - merging: {os.path.basename(f1)} and {os.path.basename(f2)}")

    #     frame = merge_files(long_file=f1, fast_file=f2)
    #     if frame.empty:
    #         continue
    #     frame.to_csv(os.path.join(path, f"sample-{num}"), sep=" ", index=False)