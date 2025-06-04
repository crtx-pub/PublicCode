import os
import json
import re
import requests
import logging


"""
This program’s purpose is to locate every .json file in a specified folder,
transform each line so that it becomes valid JSON objects inside an array,
and then send those objects in chunks no larger than 20 MB to a remote HTTP collector.
Each filename is expected to follow the convention “YYYY-MM-DD-qradar-ep8-Component.json”,
from which the script extracts the date (for “x-cortex-partition”) and component name
(for “x-cortex-source-dataset”). Robust logging is included so that if the program
fails or becomes stuck at any point, the user can inspect “process.log” to see exactly
which file, which batch, or which HTTP request was last attempted, and resume from there.
"""

# Initialize constants
archive_url_api = "" # Add your archive API here
token = "" # Add your authorization token here
folder_path = "C:\\tmp"  # Replace with your actual folder path

MAX_BYTES = 20 * 1024 * 1024  # 20 MB

# Configure logging: console + file, timestamps, levels, module name, and message
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s – %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# File handler
log_file = os.path.join(folder_path, "process.log")
file_handler = logging.FileHandler(log_file, encoding="utf-8")
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s – %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


def process_and_send(folder_path):
    """
    For each .json file under folder_path (no recursion):
      1. Read raw lines.
      2. For each line, replace "'{"→"{" and "}'"→"},", collecting processed_lines.
      3. Split processed_lines into batches so that, when wrapped in [ ... ], each batch's byte size ≤ MAX_BYTES.
         - Within each batch, remove the trailing comma on the last line before wrapping.
      4. Extract date and component from filename ("YYYY-MM-DD-qradar-ep8-Component").
      5. Send each batch as its own JSON array to the server, capturing and logging the response.
    """
    logger.info(f"Starting to process folder: {folder_path}")

    try:
        filenames = os.listdir(folder_path)
    except Exception as e:
        logger.error(f"Could not list directory '{folder_path}': {e}")
        return

    for filename in filenames:
        if not filename.endswith('.json'):
            logger.debug(f"Skipping non-JSON file: {filename}")
            continue

        full_path = os.path.join(folder_path, filename)
        if not os.path.isfile(full_path):
            logger.debug(f"Skipping '{filename}' because it's not a file.")
            continue

        logger.info(f"Reading file: {filename}")
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                raw_lines = f.readlines()
            logger.info(f"Successfully read {len(raw_lines)} lines from '{filename}'.")
        except Exception as e:
            logger.error(f"Failed to open/read '{filename}': {e}")
            continue

        # 1. Preprocess each line
        processed_lines = []
        for raw in raw_lines:
            line = raw.rstrip('\n')
            # Replace "'{" → "{" and "}'" → "},"
            line = line.replace("'{", "{").replace("}'", "},")
            if line.strip():  # skip empty lines
                processed_lines.append(line)

        if not processed_lines:
            logger.warning(f"No content to send after processing '{filename}'. Skipping.")
            continue

        # 2. Extract date and component from filename
        #    Expected format: "YYYY-MM-DD-qradar-ep8-Component.json"
        try:
            base = filename[:-5]  # drop ".json"
            date_str = base.split('-qradar')[0]      # "YYYY-MM-DD"
            component = base.split('-qradar-ep8-')[1]  # "Component"
            logger.info(f"Extracted date='{date_str}', component='{component}' from '{filename}'.")
        except Exception as e:
            logger.error(f"Filename '{filename}' does not match expected pattern: {e}")
            continue

        headers = {
            "Authorization": token,
            "x-cortex-partition": date_str,
            "x-cortex-source-dataset": component,
            "Content-Type": "application/json"
        }

        # 3. Build and send batches ≤ MAX_BYTES
        overhead = len(b"[\n") + len(b"\n]")
        batch_lines = []
        batch_size = overhead
        batch_index = 1

        def send_batch(lines, idx, size):
            """
            Given a list of JSON lines (each ending with '},'), remove the trailing comma
            from the last line, wrap in [ ... ], send to the server, and log the response.
            """
            last_line = lines[-1]
            if last_line.rstrip().endswith(','):
                lines[-1] = last_line.rstrip().rstrip(',')

            content = "[\n" + "\n".join(lines) + "\n]"
            try:
                response = requests.post(
                    url=archive_url_api,
                    headers=headers,
                    data=content.encode('utf-8'),
                    timeout=30
                )
                status = response.status_code
                resp_text = response.text[:200] + ("…" if len(response.text) > 200 else "")
            except requests.exceptions.RequestException as e:
                logger.error(f"Batch {idx} for '{filename}' failed to send: {e}")
                return

            if response.ok:
                logger.info(f"Batch {idx} for '{filename}' sent successfully (size={size} bytes, status={status}).")
            else:
                logger.error(f"Batch {idx} for '{filename}' returned {status}: {resp_text}")

        for line in processed_lines:
            encoded = (line + "\n").encode('utf-8')
            line_bytes = len(encoded)

            # If adding this line would exceed MAX_BYTES, send current batch first
            if batch_lines and (batch_size + line_bytes > MAX_BYTES):
                send_batch(batch_lines.copy(), batch_index, batch_size)
                batch_index += 1
                batch_lines.clear()
                batch_size = overhead

            batch_lines.append(line + ",")
            batch_size += line_bytes

        # Send final batch if any remain
        if batch_lines:
            send_batch(batch_lines.copy(), batch_index, batch_size)

    logger.info("Finished processing all files.")

if __name__ == "__main__":
    process_and_send(folder_path)
    logger.info("Program completed.")
