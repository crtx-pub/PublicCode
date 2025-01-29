#################################################################


#  This script is unofficial and intended solely for educational purposes. 
#  We assume no responsibility for any misuse of the script or any of its components.


#################################################################
import os
import json
import requests
from datetime import datetime

def read_and_format_logs(folder_path):
    """
    Reads and formats log files from a specified folder.

    Args:
        folder_path (str): The path to the folder containing log files.

    Returns:
        str: A message indicating the completion of the process.
    """
    for filename in os.listdir(folder_path):
        print("Reading file:", filename)
        if filename.endswith('.json'):  # Assuming the logs are in JSON format
            # Extract date from the filename
            date_str = filename.split(' ')[0]
            component = filename.split(' ')[1].split('.')[0]

            # Read the content of the file
            with open(os.path.join(folder_path, filename), 'r') as file:
                log_entries = json.load(file)
                file.close()
            print(test_http_collector(log_entries, date_str, component))

    return "Done!"

def test_http_collector(logs_body, date_obj, component):
    """
    Sends log entries to an HTTP collector.

    Args:
        logs_body (list): The log entries to be sent.
        date_obj (str): The date extracted from the filename.
        component (str): The component name extracted from the filename.

    Returns:
        Response: The response from the HTTP collector.
    """
    headers = {
        "Authorization": "", # Add your authorization token here
        "x-cortex-partition": date_obj,  # Change as needed
        "x-cortex-source-dataset": component,
        "Content-Type": "application/json"
    }

    # Prepare the body for the request
    body = "\n".join(json.dumps(log) for log in logs_body)  # Joining log entries with newline

    res = requests.post(
        url="https://api-xsiam-sedemo.xdr.us.paloaltonetworks.com/logs/v1/bulk_load",
        headers=headers,
        data=body
    )

    return res

# Main execution
folder_path = "C:\\your_folder"  # Replace with your folder path
print(read_and_format_logs(folder_path))
