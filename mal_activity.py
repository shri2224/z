import re
import csv

# ============================================================
# CONFIGURATION
# ============================================================

# Log file (can be .log OR .csv)
log_file = "test_logs.csv"      # change to logs.csv if needed


# ============================================================
# DEFINE ALL EVENTS TO DETECT (ONLY CHANGE THIS SECTION)
# ============================================================

events = [
    {
        "name": "Failed SSH Login",
        "event_regex": r"Failed password",
        "ip_regex": r"\d+\.\d+\.\d+\.\d+",
        "info_regex": r"for (\w+)",
        "date_regex": r"^([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})",
        "message": "made failed login attempts",
        "results": {}
    },
    {
        "name": "SQL Injection",
        "event_regex": r"(union select|or '1'='1'|--)",
        "ip_regex": r"\d+\.\d+\.\d+\.\d+",
        "info_regex": r"(\/\S+)",
        "date_regex": r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})",
        "message": "made SQL injection attempts",
        "results": {}
    },
    {
        "name": "Directory Traversal",
        "event_regex": r"(\.\./|%2e%2e%2f)",
        "ip_regex": r"\d+\.\d+\.\d+\.\d+",
        "info_regex": r"(\/\S+)",
        "date_regex": r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})",
        "message": "attempted directory traversal",
        "results": {}
    },
    {
        "name": "XSS Attack",
        "event_regex": r"(<script>|%3cscript%3e)",
        "ip_regex": r"\d+\.\d+\.\d+\.\d+",
        "info_regex": r"(\/\S+)",
        "date_regex": r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})",
        "message": "attempted cross-site scripting",
        "results": {}
    }
]


# ============================================================
# PRE-COMPILE REGEX (PERFORMANCE + CLEAN CODE)
# ============================================================

for event in events:
    event["event_pattern"] = re.compile(event["event_regex"], re.IGNORECASE)
    event["ip_pattern"] = re.compile(event["ip_regex"])
    event["info_pattern"] = re.compile(event["info_regex"])
    event["date_pattern"] = re.compile(event["date_regex"])


# ============================================================
# UNIVERSAL FILE READER (LOG + CSV)
# ============================================================

def read_log_lines(file_path):
    """
    Reads both:
    - .log files (line by line)
    - .csv files (row by row → converted to string)

    Returns ONE line at a time as a STRING
    """

    if file_path.endswith(".csv"):
        with open(file_path, newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Convert CSV row to log-style string
                yield " ".join(row.values())
    else:
        with open(file_path) as file:
            for line in file:
                yield line


# ============================================================
# MAIN ANALYSIS LOGIC (DO NOT CHANGE)
# ============================================================

for line in read_log_lines(log_file):

    for event in events:

        # Step 1: Check if this line contains the attack pattern
        if not event["event_pattern"].search(line):
            continue

        # Step 2: Extract IP address
        ip_match = event["ip_pattern"].search(line)
        if not ip_match:
            continue
        ip = ip_match.group()

        # Step 3: Extract user / URL / info
        info_match = event["info_pattern"].search(line)
        info = info_match.group(1) if info_match else "unknown"

        # Step 4: Extract date & time
        date_match = event["date_pattern"].search(line)
        date_time = date_match.group(1) if date_match else "unknown date"

        # Step 5: Count occurrences
        key = (ip, info, date_time)
        event["results"][key] = event["results"].get(key, 0) + 1


# ============================================================
# OUTPUT
# ============================================================

for event in events:
    print(f"\n=== {event['name']} ===")

    if not event["results"]:
        print("No events detected.")
        continue

    for (ip, info, date_time), count in event["results"].items():
        print(
            f"[{date_time}] {info} "
            f"{event['message']} {count} times from IP {ip}"
        )
