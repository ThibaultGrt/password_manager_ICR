from base64 import b64encode
from base64 import b64decode
import json
from argon2 import PasswordHasher
from argon2 import low_level
import db_helper as db
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

time = 1000
memory = 65536
parallelism = 4
hash_len = 32
salt_len = 16
encoding = 'utf-8'

ph = PasswordHasher(time_cost=time, memory_cost=memory, parallelism=parallelism, hash_len=hash_len, salt_len=salt_len, encoding=encoding)

### Hash functions ###

def compute_hash(pwd):
    return ph.hash(pwd)

def compute_hash_from_salt(pwd, salt):
    if salt == None:
        salt = Random.get_random_bytes(16) # why cast in bytes ?
    res = low_level.hash_secret_raw(bytes(pwd, 'utf-8'), salt, time_cost=time, memory_cost=memory, parallelism=parallelism, hash_len=hash_len, type=low_level.Type.ID)
    return res, salt

def verify_hash(username, pwd):
    try:
        return ph.verify(db.get_from_user(username, "fingerprint"), pwd)
    except Exception:
        print("Error : ", "The password is not correct")

### Cipher functions with Chacha20 ###

def encrypt(key, plaintext, header=None):
    cipher = ChaCha20_Poly1305.new(key=key)
    if header != None:
        cipher.update(bytes(header,'utf-8'))
    if not isinstance(plaintext, bytes):
        plaintext = bytes(plaintext, 'utf-8')
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    jk = [ 'nonce', 'tag', 'ciphertext']
    jv = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, tag, ciphertext) ]
    return json.dumps(dict(zip(jk, jv)))


def decrypt(key, cipher_struct, header=None):
    try:
        b64 = json.loads(cipher_struct)
        jk = ['nonce', 'tag', 'ciphertext']
        jv = {k:b64decode(b64[k]) for k in jk}
        cipher = ChaCha20_Poly1305.new(key=key, nonce=jv['nonce'])
        if header != None:
            cipher.update(bytes(header,'utf-8'))
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        return plaintext
    except Exception as e:
        print(e)

### Public key encryption functions ###

def generate_and_store_rsa_key(user, key):
    try:
        rsa_key = RSA.generate(2048)
        # encrypt the private key
        enc_private_key = bytes(encrypt(key, rsa_key.export_key()), 'utf-8')
        #store the private key
        db.store_private(user, enc_private_key)
        #store the public key
        db.store_public(user, rsa_key.publickey().export_key())
    except Exception as e:
        print("Can't create/store RSA key pair: ", e)


def share_password(sender, passwords_key, receiver, site):
    try:
        chacha_password = db.get_site_password(sender, site)
        password = decrypt(passwords_key, chacha_password, site)
        enc_password = b64encode(rsa_encryption(receiver, password)).decode('utf-8') #B64 no need
        db.store_shared(sender, receiver, site, enc_password)
        return True
    except Exception as e:
        print("Can't share :", e)


def rsa_encryption(receiver, password):
    try:
        public_key = db.get_public(receiver)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_password = cipher_rsa.encrypt(password)
        return enc_password
    except Exception as e:
        print("Can't encrypt: ", e)
    

## Cut in 2 functions
def rsa_decryption(receiver, key, sender, site):
    try:
        enc_private_key = db.get_private(receiver)
        key_obj = decrypt(key, enc_private_key)
        private_key = RSA.import_key(key_obj)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        enc_password = b64decode(db.get_shared_password(receiver, sender, site))
        password = cipher_rsa.decrypt(enc_password)
        return password.decode()
    except Exception as e:
        print("Can't decrypt RSA : ", e)
    

### Others functions ###

def verify_login(username, password):
    return db.has_user(username) and verify_hash(username, password)

def create_account(user, pwd):
    try:
        #empreinte du mot de passe
        fingerprint = compute_hash(pwd)
        master_key, salt = compute_hash_from_salt(pwd, None)
        b64salt = b64encode(salt).decode('utf-8')
        passwords_key = Random.get_random_bytes(32)
        cipher_passwords_key = encrypt(master_key, passwords_key)
        generate_and_store_rsa_key(user, passwords_key)
        if db.store_account(user, fingerprint, b64salt, cipher_passwords_key):
            db.initialize_files(user)
            return True
    except Exception:
        print("Can't create the account")

def change_password(user, pwd, new_pwd):
    try:
        new_fingerprint = compute_hash(new_pwd)
        new_master_key, new_salt = compute_hash_from_salt(new_pwd, None)
        new_b64salt = b64encode(new_salt).decode('utf-8')
        #get the cipher passwords key
        cipher_passwords_key = db.get_from_user(user, 'cipher_passwords_key')
        # Decrypt passwords key with the global master key
        master_key = generate_master_key(user, pwd) # TODO: Retourner la master_key pour la passer en paramètre
        passwords_key = decrypt(master_key, cipher_passwords_key)
        # Reencrypt with the new master key
        new_cipher_passwords_key = encrypt(new_master_key, passwords_key)
        return db.update_master_password(user, new_fingerprint, new_b64salt, new_cipher_passwords_key)
    except Exception as e:
        print("Can't change your password : ", e)

def generate_master_key(user, password):
    try:
        key_salt = b64decode(db.get_from_user(user, "master_key_salt"))
        master_key, salt = compute_hash_from_salt(password, key_salt)
        return master_key
    except Exception as e:
        print("Error : ", e)

def decrypt_passwords_key(user, master_key):
    cipher_passwords_key = db.get_from_user(user, 'cipher_passwords_key')
    passwords_key = decrypt(master_key, cipher_passwords_key)
    return passwords_key


def add_password(user, site, password, passwords_key):
    try:
        cipher_password = encrypt(passwords_key, password, header=site) #Pass the site as header to mac it without encrypt
        return db.store_password(user, site, cipher_password)
    except Exception:
        print("Can't save your password")


def get_password(user, site, passwords_key):
    try:
        cipher_password = db.get_site_password(user, site)
        plaintext = decrypt(passwords_key, cipher_password, site)
        return plaintext.decode()
    except Exception as e:
        print("Can't get the password : ", e)

if __name__=="__main__":
    print("You are running the helper of this password manager")
    key = RSA.generate(2048)
    private_key = key.export_key()
    print(private_key)
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    print(public_key)
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()