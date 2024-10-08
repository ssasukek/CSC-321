from Crypto.Cipher import AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
import urllib.parse


# generate key or iv
def gen_key_iv():
    return get_random_bytes(16)


# add padding to data so that its length is a multiple of 16 (bytes)
def pad(data):
    padding = 16 - (len(data) % 16)
    # return bytes(data, encoding='utf-8') + bytes([padding] * padding)
    return data + bytes([padding] * padding)


# remove padding from data
def unpad(data):
    padding = data[-1]
    return data[:-padding]


def submit(input, key, iv):     #done
    prepend = "userid=456;userdata="
    append = ";session-id=31337"

    string = prepend + input + append # prepend and append strings to input

    encoded_data = urllib.parse.quote(string, safe='') # URL encode ; and =

    # padded_data = pad(encoded_data) # pad data
    padded_data = pad(encoded_data.encode()) # pad data

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded_data) # encrypt using AES-128-CBC

    return encrypted


def verify(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data)
    
    # decoded = urllib.parse.unquote(unpadded_data)
    decoded = urllib.parse.unquote(unpadded_data.decode('utf-8', 'ignore'))
    
    pattern = ";admin=true;"

    print(f"Decrypted data: {decoded}")

    return pattern in decoded


def attack(ciphertext, injection, block_size=16):
    # convert ct to byte array
    modified_ciphertext = bytearray(ciphertext)

    target = bytes(injection, 'utf-8')
    injection_block = len(ciphertext) - block_size * 2

    for i in range(len(target)):
        # modified_ciphertext[i] ^= target[i] ^ ord("?")
        # modified_ciphertext[i] ^= ord("?") ^ target[i]
        modified_ciphertext[injection_block + i] ^= ord('?') ^ target[i]
        # modified_ciphertext[injection_block + i] ^= target[i] ^ ord('?')


    return bytes(modified_ciphertext)


if __name__ == '__main__':
    key = gen_key_iv()
    iv = gen_key_iv()

    ciphertext = submit("You're the man now, dog", key, iv)
    print("Original Verify:", verify(ciphertext, key, iv))

    # bit flipping attack
    modified_ciphertext = attack(ciphertext, ";admin=true;")

    #verify tampered
    is_admin = verify(modified_ciphertext, key, iv)

    print(f"Second Verify after attack: {is_admin}")
