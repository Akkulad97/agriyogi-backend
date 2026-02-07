from blockchain import Session, BlockModel

s = Session()
rows = s.query(BlockModel).all()

print('Photo sizes in database after compression:')
for r in rows:
    photo_size = len(r.photo_base64 or '') / 1024
    print(f"Block {r.idx}: verified_by={r.verified_by}, photo_size={photo_size:.1f} KB")
