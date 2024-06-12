"""
JSON Signature Generator Service

This script reads a JSON file path from its STDIN, generates its signature, ignoring
elements order, and print result to STDOUT. It run as a service. The file test_common.c
will start this service and will send filenames to it through pipe.

It is optimized as a service since it is being used extensively in the test suite.
"""
import json
import hashlib
import sys
import logging

logging.getLogger().disabled = True
# logging.basicConfig(filename='./json_signature_generator.log', level=logging.INFO,
#                     format='%(asctime)s - %(levelname)s - %(message)s')

def load_json(file_path):
    try:
        with open(file_path, 'r') as file:
            file_content = file.read()

        file_content = file_content.rstrip(",\r\n")

        # rdb-cli doesn't produce valid JSON. It requires few adaptations
        # [ ... ]               ==> { "dbs": [ ... ] }
        # "a":"b" .... "y":"z"  ==> { "a":"b" .... "y":"z" }
        if file_content.startswith('['):
            file_content = '{ "dbs":' + file_content + '}'
        elif not file_content.startswith('{'):
            file_content = '{' + file_content + '}'

        data = json.loads(file_content)
        return data
    except Exception as e:
        logging.error(f"Error loading JSON file {file_path}: {str(e)}")
        raise

def sort_json(data):
    if isinstance(data, dict):
        sorted_dict = {key: sort_json(data[key]) for key in sorted(data)}
        return sorted_dict
    elif isinstance(data, list):
        return sorted((sort_json(item) for item in data), key=lambda x: json.dumps(x))
    else:
        return data

def json_to_string(data):
    return json.dumps(data, separators=(',', ':'), ensure_ascii=False)

def generate_signature(data_string):
    return hashlib.sha256(data_string.encode('utf-8')).hexdigest()

def service():
    logging.info(f"Starting JSON Signature Generator Service")
    while True:
        try:
            # Read file path from standard input
            file_path = sys.stdin.readline().strip()

            if not file_path:
                break

            # Process the file
            json_data = load_json(file_path)
            sorted_json_data = sort_json(json_data)
            sorted_json_string = json_to_string(sorted_json_data)
            signature = generate_signature(sorted_json_string)

            # Return the signature
            print(signature)
            logging.info(f"Signature generated for file: {file_path}")
            sys.stdout.flush() # Flush STDOUT, ensure it's sent immediately

        except Exception as e:
            logging.error(f"Error processing file: {file_path}, Error: {str(e)}")
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.stderr.flush()
            continue

if __name__ == "__main__":
    service()
