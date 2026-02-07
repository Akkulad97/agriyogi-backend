import blockchain

print('Testing blockchain initialization...')
blockchain.create_initial_chain()
chain = blockchain.get_chain()

print(f'\nChain length: {len(chain)}')
for b in chain:
    has_photo = bool(getattr(b, 'photo_base64', None))
    verified = getattr(b, 'verified_by', None)
    print(f'Block #{b.index}: data={b.data[:40]}, verified_by={verified}, has_photo={has_photo}')
