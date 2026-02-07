"""Compress existing large photos in database"""
from blockchain import Session, BlockModel
from PIL import Image
import io
import base64

def compress_image(photo_base64_str, max_width=400, max_height=400, quality=75):
    """Decompress base64 photo, compress it, and return new base64"""
    try:
        # Decode from base64
        photo_bytes = base64.b64decode(photo_base64_str)
        # Open and process
        img = Image.open(io.BytesIO(photo_bytes))
        if img.mode == 'RGBA':
            rgb_img = Image.new('RGB', img.size, (255, 255, 255))
            rgb_img.paste(img, mask=img.split()[3] if len(img.split()) == 4 else None)
            img = rgb_img
        img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=quality, optimize=True)
        return base64.b64encode(output.getvalue()).decode('utf-8')
    except Exception as e:
        print(f'Failed to compress: {e}')
        return photo_base64_str

s = Session()
rows = s.query(BlockModel).filter(BlockModel.photo_base64 != None).all()

for r in rows:
    old_size = len(r.photo_base64 or '') / 1024
    if old_size > 10:  # Only compress if > 10KB
        print(f'Block {r.idx}: compressing {old_size:.1f}KB...')
        r.photo_base64 = compress_image(r.photo_base64)
        new_size = len(r.photo_base64 or '') / 1024
        print(f'  → {new_size:.1f}KB')
        s.add(r)

s.commit()
s.close()
print('Done!')
