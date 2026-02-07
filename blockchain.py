import hashlib
import time
import os
import secrets
import hmac
from sqlalchemy import create_engine, Column, Integer, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from werkzeug.security import generate_password_hash, check_password_hash

# Database filename (stored next to this module)
DB_FILE = os.path.join(os.path.dirname(__file__), 'ledger.db')
ENGINE = create_engine(f'sqlite:///{DB_FILE}', connect_args={'check_same_thread': False})
Session = sessionmaker(bind=ENGINE)
Base = declarative_base()


class BlockModel(Base):
    __tablename__ = 'blocks'
    idx = Column('idx', Integer, primary_key=True)
    timestamp = Column('timestamp', Text)
    data = Column('data', Text)
    previous_hash = Column('previous_hash', Text)
    hash = Column('hash', Text)
    author = Column('author', Text, nullable=True)
    signature = Column('signature', Text, nullable=True)
    photo_base64 = Column('photo_base64', Text, nullable=True)
    verified_by = Column('verified_by', Text, nullable=True)


class UserModel(Base):
    __tablename__ = 'users'
    id = Column('id', Integer, primary_key=True)
    username = Column('username', Text, unique=True)
    password_hash = Column('password_hash', Text)
    hmac_key = Column('hmac_key', Text)


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        value = str(self.index) + self.timestamp + str(self.data) + self.previous_hash
        return hashlib.sha256(value.encode()).hexdigest()


blockchain = []


def init_db():
    try:
        # Create tables via SQLAlchemy
        Base.metadata.create_all(ENGINE)
        return True
    except Exception:
        return False


def save_block(block):
    try:
        session = Session()
        model = session.query(BlockModel).get(block.index)
        if not model:
            model = BlockModel(idx=block.index, timestamp=block.timestamp,
                               data=block.data, previous_hash=block.previous_hash,
                               hash=block.hash)
        else:
            model.timestamp = block.timestamp
            model.data = block.data
            model.previous_hash = block.previous_hash
            model.hash = block.hash
        session.add(model)
        session.commit()
        session.close()
        return True
    except Exception:
        return False


def load_ledger():
    try:
        session = Session()
        rows = session.query(BlockModel).order_by(BlockModel.idx).all()
        session.close()
        if not rows:
            return False
        blockchain.clear()
        for item in rows:
            b = Block(item.idx, item.timestamp, item.data, item.previous_hash)
            if b.hash != item.hash:
                b.hash = item.hash
            # attach author/signature/photo/verified_by attributes for in-memory use
            b.author = getattr(item, 'author', None)
            b.signature = getattr(item, 'signature', None)
            b.photo_base64 = getattr(item, 'photo_base64', None)
            b.verified_by = getattr(item, 'verified_by', None)
            blockchain.append(b)
        return True
    except Exception:
        return False


def create_user(username, password):
    session = Session()
    existing = session.query(UserModel).filter_by(username=username).first()
    if existing:
        session.close()
        return False, 'user_exists'
    pw_hash = generate_password_hash(password)
    hkey = secrets.token_hex(32)
    user = UserModel(username=username, password_hash=pw_hash, hmac_key=hkey)
    session.add(user)
    session.commit()
    session.close()
    return True, None


def authenticate_user(username, password):
    session = Session()
    user = session.query(UserModel).filter_by(username=username).first()
    session.close()
    if not user:
        return False
    return check_password_hash(user.password_hash, password)


def get_user_hmac_key(username):
    session = Session()
    user = session.query(UserModel).filter_by(username=username).first()
    session.close()
    if not user:
        return None
    return bytes.fromhex(user.hmac_key)


def save_block_with_meta(block, author=None, signature=None, photo_base64=None, verified_by=None):
    # Save block and attach metadata
    try:
        session = Session()
        model = session.query(BlockModel).get(block.index)
        if not model:
            model = BlockModel(idx=block.index, timestamp=block.timestamp,
                               data=block.data, previous_hash=block.previous_hash,
                               hash=block.hash, author=author, signature=signature,
                               photo_base64=photo_base64, verified_by=verified_by)
        else:
            model.timestamp = block.timestamp
            model.data = block.data
            model.previous_hash = block.previous_hash
            model.hash = block.hash
            model.author = author
            model.signature = signature
            model.photo_base64 = photo_base64
            model.verified_by = verified_by
        session.add(model)
        session.commit()
        session.close()
        # Keep in-memory block in sync so API responses include metadata immediately.
        try:
            block.author = author
            block.signature = signature
            block.photo_base64 = photo_base64
            block.verified_by = verified_by
        except Exception:
            pass
        return True
    except Exception:
        return False


def verify_chain():
    problems = []
    for i in range(1, len(blockchain)):
        prev = blockchain[i-1]
        cur = blockchain[i]
        if cur.previous_hash != prev.hash:
            problems.append({'index': cur.index, 'problem': 'previous_hash_mismatch'})
        # verify hash integrity
        to_hash = str(cur.index) + cur.timestamp + str(cur.data) + cur.previous_hash
        recalculated = hashlib.sha256(to_hash.encode()).hexdigest()
        if recalculated != cur.hash:
            problems.append({'index': cur.index, 'problem': 'hash_mismatch'})
        # verify signature if author present
        if hasattr(cur, 'author') and cur.author:
            key = get_user_hmac_key(cur.author)
            if key:
                expected = hmac.new(key, cur.hash.encode(), hashlib.sha256).hexdigest()
                if getattr(cur, 'signature', None) != expected:
                    problems.append({'index': cur.index, 'problem': 'bad_signature'})
            else:
                problems.append({'index': cur.index, 'problem': 'unknown_author'})
    return problems


def create_initial_chain():
    # Initialize DB and try to load from it first
    init_db()
    if load_ledger():
        return
    genesis = Block(0, time.ctime(), "First tomato batch planted", "0")
    blockchain.append(genesis)
    save_block(genesis)
    add_block("Compost applied")
    add_block("Harvested tomatoes")


def add_block(data):
    previous_hash = blockchain[-1].hash if blockchain else "0"
    index = (blockchain[-1].index + 1) if blockchain else 0
    block = Block(index, time.ctime(), data, previous_hash)
    blockchain.append(block)
    save_block(block)
    return block


def get_chain():
    return blockchain
