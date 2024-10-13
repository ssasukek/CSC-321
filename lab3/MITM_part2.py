# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import dh
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
from hashlib import sha256
import random

# q = 37      # small prime
# g = 5       # generator 

q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBC"
        "FB06A3C69A6A9DCA52D23B616073E28675A23D18"
        "9838EF1E2EE652C013ECB4AEA906112324975C3C"
        "D49B83BFACCBDD7D90C4BD7098488E9C219A7372"
        "4EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F" 
        "0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
        "DF1FB2BC2E4A4371", 16)

# g = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD2"
#         "58AC507FD6406CFF14266D31266FEA1E5C41564B"
#         "777E690F5504F213160217B4B01B886A5E91547F" 
#         "9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76"
#         "A6A24C087A091F531DBF0A0169B6A28AD662A4D1"
#         "8E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
#         "855E6EEB22B3B2E5", 16)

g = 1


# name of the attacker
class Mallory:
    # YA
    def intercept_a_public_key(self, YA):
        print("Mallory has changed Alice's public key to q and send to Bob")
        return q        #Bob will now recieve q instead of YA
    
    # YB
    def intercept_b_public_key(self, YB):
        print("Mallory has changed Bob's public key to q and send to Alice")
        return q        #Alice will now recieve q instead of YB


def generate_private_key(q):
    return random.randint(1, q)

def computing_public_key(g, private_key, q):
    return pow(g, private_key, q)

def computing_shared_secret(public_key, private_key, q):
    return pow(public_key, private_key, q)

# derive key (calculate an input containing public and secret data - a key that used instead of ori or password)
def derived_key(shared_secret):
    # Use SHA256 to derive a 16-byte key from the shared secret
    hash_alg = sha256(str(shared_secret).encode())
    derived = hash_alg.digest()[:16]
    return derived


def diffie_hellman_protocol():

    # Alice's private and public key
    a_private_key = generate_private_key(q)
    a_public_key = computing_public_key(g, a_private_key, q)

    # Bob's private and public key
    b_private_key = generate_private_key(q)
    b_public_key = computing_public_key(g, b_private_key, q)

    # shared key betwwen alice and bob
    a_shared_secret = computing_shared_secret(b_public_key, a_private_key, q)
    b_shared_secret = computing_public_key(a_public_key, b_private_key, q)

    # ensure they are the same share secret msg
    assert a_shared_secret == b_shared_secret

    shared_key = derived_key(a_shared_secret)

    # Alice's msg to Bob - encrypted
    a_msg = "Hi Bob!"
    a_encrypt_msg = encrypt_msg(shared_key, a_msg)

    # Bob's msg to Alice - encrypted
    b_msg = "Hi Alice!"
    b_encrypt_msg = encrypt_msg(shared_key, b_msg)

    a_decrypt_msg = decrypt_msg(shared_key, a_encrypt_msg)
    b_decrypt_msg = decrypt_msg(shared_key, b_encrypt_msg)

    print("Alice's message to Bob:", a_decrypt_msg)
    print("Bob's message to Alice:", b_decrypt_msg)

    #test
    print("Alice's encrypted msg to Bob:", a_encrypt_msg)
    print("Bob's encrypted msg to Alice:", b_encrypt_msg)

    # mallory computes the shared key
    # when mallory sets g = 1, both of them compute s = 1^a mod q which is 1
    mal_key = computing_shared_secret(1, 1, q)
    key = derived_key(mal_key)
    a_decrypt_msg = decrypt_msg(key, a_encrypt_msg)
    b_decrypt_msg = decrypt_msg(key, b_encrypt_msg)

    print("Mallory decript's Alice's message: ", a_decrypt_msg)
    print("Mallory decript's Bob's message: ", b_decrypt_msg)


# add padding to data so that its length is a multiple of 16 (bytes)
def pad(data):  # done
    padding = 16 - (len(data) % 16)
    return data + bytes([padding] * padding)

# remove padding from data
def unpad(data):  # done
    padding = data[-1]
    return data[:-padding]

# AES-CBC encryption
def encrypt_msg(key, msg):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(msg.encode())
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

# AES-CBC decryption
def decrypt_msg(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypt_data = cipher.decrypt(ciphertext)
    decoded_data = unpad(decrypt_data[16:]).decode()
    return decoded_data    


if __name__ == "__main__":
    diffie_hellman_protocol()