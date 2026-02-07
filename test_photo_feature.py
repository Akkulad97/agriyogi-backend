import requests
import base64
import os

# Create a simple test image
test_img_path = '/tmp/test.jpg'
os.makedirs('/tmp', exist_ok=True)
with open(test_img_path, 'wb') as f:
    # Minimal JPEG file
    f.write(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + b'\x00' * 1000 + b'\xff\xd9')

s = requests.Session()

# Login
login_resp = s.post('http://127.0.0.1:5000/api/login', json={'username': 'smoketest', 'password': 'TestPass123'})
print(f"Login: {login_resp.status_code} - {login_resp.json()}")

# Mine with photo and verified_by
with open(test_img_path, 'rb') as f:
    files = {
        'data': (None, 'Testing photo and verified_by feature'),
        'verified_by': (None, 'Quality Inspector'),
        'photo': ('test.jpg', f, 'image/jpeg')
    }
    mine_resp = s.post('http://127.0.0.1:5000/api/mine', files=files)
    print(f"Mine: {mine_resp.status_code}")
    print(f"Response: {mine_resp.json()}")

# Fetch blocks
blocks_resp = s.get('http://127.0.0.1:5000/api/blocks')
print(f"\nBlocks: {blocks_resp.status_code}")
blocks = blocks_resp.json().get('blocks', [])
for b in blocks[-2:]:
    has_photo = 'Yes' if b.get('photo_base64') else 'No'
    verified = b.get('verified_by') or 'N/A'
    print(f"Block #{b['index']}: verified_by={verified}, has_photo={has_photo}")
