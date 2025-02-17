import database
from diffhtml import *
import logging
import mutate
import json
import report_html
import time
import subprocess

FLAG = "BASELINE_DIFF"

def to_file(filename, content):
    with open(filename, 'w') as f:
        f.write(content)

def process_baseline(records):
    to_file("html1.html", records[0][4].decode("utf-8"))

    for record in records:
        if records[0][4] != record[4]:
            break
    else:  # if all baselines are identical
        global FLAG
        FLAG = "BASELINE_SAME"
        return records[0][4].decode("utf-8")

    to_file("html2.html", records[1][4].decode("utf-8"))

    parser = EDEFuzzHTMLParser()
    parser.feed(records[0][4].decode("utf-8"))
    DOM = parser.dom
    for i in range(1, len(records)):
        parser_t = EDEFuzzHTMLParser()
        parser_t.feed(records[i][4].decode("utf-8"))
        DOM_t = parser_t.dom
        DOM.mark_uncommon(DOM_t)

    return DOM

def compare(baseline, record):
    if isinstance(baseline, str):
        return baseline == record
    parser = EDEFuzzHTMLParser()
    parser.feed(record)
    DOM = parser.dom
    return baseline == DOM

def capture_snapshot(target):
    """Capture the state of the application."""
    db = database.Connection(target)
    baseline_records = db.get_baseline()
    if not baseline_records:
        print("No baselines available to capture snapshot.")
        return None

    snapshot = process_baseline(baseline_records)
    return snapshot

def fuzz_using_snapshot(snapshot, target):
    """Perform fuzzing based on the captured snapshot."""
    db = database.Connection(target)
    executed = 0
    with open("tests/" + target + ".json", "r") as f:
        response = json.load(f)

    total = sum(1 for _ in mutate.leaf(response))
    flagged_count = 0

    for record in db.get_result():
        executed += 1
        if compare(snapshot, record[4].decode("utf-8")):
            flagged_count += 1

    print(f"{flagged_count} / {total} field(s) flagged based on snapshot.")
    return flagged_count, total

def report(target):
    # Setting up logger for reporting
    logger = logging.getLogger("log")
    ch = logging.FileHandler("report_stat.csv")
    logger.addHandler(ch)

    FLAG_NO_BASELINE = False

    # Capture the snapshot
    snapshot = capture_snapshot(target)
    if snapshot is None:
        FLAG_NO_BASELINE = True
        logger.error("No baseline found for target: " + target)
        return

    # Fuzz using the captured snapshot
    flagged_count, total = fuzz_using_snapshot(snapshot, target)

    # Returning the flagged count for further processing if needed
    return flagged_count, total

if __name__ == "__main__":
    # Snapshot-based fuzzing execution
    target = "wikipedia"
    print("Starting snapshot-based fuzzing...")
    start_snapshot_time = time.time()
    snapshot_flagged_count, total = report(target)
    snapshot_time = time.time() - start_snapshot_time

    # Running the normal fuzzing subprocess
    print("\nRunning normal fuzzing as subprocess with 'f' and 'r' arguments...")
    start_normal_time = time.time()
    subprocess.run(['python3', 'fuzzer.py', 'f', 'wikipedia'])
    normal_time = time.time() - start_normal_time

    # Running the 'r' command to analyze results
    subprocess.run(['python3', 'fuzzer.py', 'r', 'wikipedia'])

    # Displaying the contents of the results file
    with open('tests/wikipedia.csv', 'r') as f:
        print(f.read())

    # Print time difference
    time_difference = snapshot_time - normal_time
    print(f"\nSnapshot-based fuzzing took: {snapshot_time:.4f} seconds")
    print(f"Normal fuzzing took: {normal_time:.4f} seconds")
    print(f"Time difference (snapshot - normal): {time_difference:.4f} seconds")
