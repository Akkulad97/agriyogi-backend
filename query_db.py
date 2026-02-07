from blockchain import Session, BlockModel
import json

s = Session()
rows = s.query(BlockModel).order_by(BlockModel.idx).all()
out = []
for r in rows:
    out.append({
        'idx': r.idx,
        'timestamp': r.timestamp,
        'data': r.data,
        'previous_hash': r.previous_hash,
        'hash': r.hash,
        'author': r.author,
        'signature': r.signature,
        'verified_by': getattr(r, 'verified_by', None),
        'photo_base64_len': len(getattr(r, 'photo_base64', '') or '') or None
    })
print(json.dumps(out, indent=2))
