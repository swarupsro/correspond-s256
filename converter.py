import os
import requests

api_key = 'input api key from virustotal'

input_filename = 'hashes.txt'
output_filename = 'sha256_hashes.txt'

script_dir = os.path.dirname(os.path.abspath(__file__))

input_file = os.path.join(script_dir, input_filename)
output_file = os.path.join(script_dir, output_filename)

base_url = 'https://www.virustotal.com/api/v3/files/'

headers = {
    'x-apikey': api_key
}

with open(input_file, 'r') as file:
    hashes = file.read().splitlines()

with open(output_file, 'w') as file:
    for hash_value in hashes:
        response = requests.get(base_url + hash_value, headers=headers)
        if response.status_code == 200:
            data = response.json()
            sha256 = data['data']['attributes']['sha256']
            result = f'{sha256}'
        else:
            result = f'Error: Unable to fetch SHA-256 for {hash_value}'
        
        if 'Error' not in result:
            file.write(result + '\n')

        print(result)

print(f'SHA-256 hashes written to {output_filename}')
