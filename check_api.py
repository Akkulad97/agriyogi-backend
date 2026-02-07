import requests
import json

r = requests.get('http://127.0.0.1:5000/api/blocks')
data = r.json()
blocks = data.get('blocks', [])

print(f'Total blocks: {len(blocks)}\n')

for b in blocks:
    photo_size = len(b.get('photo_base64', '') or '') / 1024
    print(f"Block #{b['index']}:")
    print(f"  Data: {b['data'][:60]}")
    print(f"  Author: {b.get('author', 'N/A')}")
    print(f"  Verified by: {b.get('verified_by', 'N/A')}")
    print(f"  Has photo: {bool(b.get('photo_base64'))} ({photo_size:.1f} KB)")
    print()
