import os
import requests

# Your VirusTotal API key
api_key = 'input the key from virus total'

# File names
input_filename = 'hashes.txt'
output_filename = 'sha256_hashes.txt'

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct full file paths
input_file = os.path.join(script_dir, input_filename)
output_file = os.path.join(script_dir, output_filename)

# Base URL for VirusTotal API
base_url = 'https://www.virustotal.com/api/v3/files/'

headers = {
    'x-apikey': api_key
}

# Read hashes from the input file
with open(input_file, 'r') as file:
    hashes = file.read().splitlines()

# Open the output file in write mode
with open(output_file, 'w') as file:
    for hash_value in hashes:
        response = requests.get(base_url + hash_value, headers=headers)
        if response.status_code == 200:
            data = response.json()
            sha256 = data['data']['attributes']['sha256']
            result = f'{sha256}'
        else:
            result = f'Error: Unable to fetch SHA-256 for {hash_value}'
        
        # Write the SHA-256 hash to the output file if no error
        if 'Error' not in result:
            file.write(result + '\n')
        
        # Print the result to the console
        print(result)

print(f'SHA-256 hashes written to {output_filename}')
