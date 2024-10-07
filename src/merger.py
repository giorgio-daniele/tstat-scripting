import os
import shutil
import pandas
import shutil
import argparse

def merge_files(long_file: str, fast_file: str):

    # print(long_file)
    # print(fast_file)
    # print()

    # read both csv files into dataframes
    long_frame = pandas.read_csv(long_file, sep=" ")
    fast_frame = pandas.read_csv(fast_file, sep=" ")

    #print(long_frame)
    
    # create an empty list to store the resulting rows
    records = []

    # loop over each row in long_frame (10-second samples)
    for index, row1 in long_frame.iterrows():
        ts_f1 = row1['ts']  # start time from long_frame
        te_f1 = row1['te']  # end time from long_frame

        # find all rows in fast_frame whose ts and te are within the interval [ts_f1, te_f1]
        sub = fast_frame[(fast_frame['ts'] >= ts_f1) & (fast_frame['te'] <= te_f1)]

        if sub.empty:
            continue
        
        # flatten matching rows from fast_frame into a single row (side by side)
        flat = sub.values.flatten()

        # create new column names for the matching rows
        cols = []
        for i in range(1, len(sub) + 1):
            cols += [f"{col}_#{i}" for col in fast_frame.columns]
        
        # convert row1 to a list and combine with flattened matching rows
        rows = pandas.DataFrame([row1.tolist() + flat.tolist()], columns=list(long_frame.columns) + cols)
        
        # append the combined row to the final list
        records.append(rows)

    # check if any records were added before concatenating
    if records:
        # concatenate all combined rows to form the final dataframe
        frame = pandas.concat(records, ignore_index=True)
        # remove columns containing 'requests' or 'audio'
        frame = frame.loc[:, ~frame.columns.str.contains('requests|audio', case=False)]
    else:
        print("No matching records found.")
        frame = pandas.DataFrame()  # return an empty DataFrame if no records were added
    
    return frame

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)

    args = parser.parse_args()

    # define the path for the new data folder
    path = os.path.join(args.folder, "dataset")

    # remove existing data folder and create a new one
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path)

    # define media folder paths
    fast_samples = os.path.join(args.folder, "data", "mix", "1000")
    long_samples = os.path.join(args.folder, "data", "mix", "10000")

    # get the files
    fast_files = sorted([os.path.join(fast_samples, f) for f in os.listdir(fast_samples)])
    long_files = sorted([os.path.join(long_samples, f) for f in os.listdir(long_samples)])

    for num, (f1, f2) in enumerate(zip(long_files, fast_files)):

        print(f"Processing folder: {path}")
        print(f"  - merging: {os.path.basename(f1)} and {os.path.basename(f2)}")

        frame = merge_files(long_file=f1, fast_file=f2)
        if frame.empty:
            continue
        frame.to_csv(os.path.join(path, f"sample-{num}"), sep=" ", index=False)
    




