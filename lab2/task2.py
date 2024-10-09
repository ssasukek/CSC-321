# from Crypto.Cipher import AES # type: ignore
# from Crypto.Random import get_random_bytes # type: ignore
# from Crypto.Util.Padding import pad, unpad # type: ignore
# import urllib.parse


# # generate key or iv
# def gen_key_iv():
#     return get_random_bytes(16)


# # add padding to data so that its length is a multiple of 16 (bytes)
# def pad(data):
#     padding = 16 - (len(data) % 16)
#     return data + bytes([padding] * padding)


# # remove padding from data
# def unpad(data):
#     padding = data[-1]
#     return data[:-padding]

# def submit(input, key, iv):     #done
#     prepend = "userid=456;userdata="
#     append = ";session-id=31337"

#     string = prepend + input + append # prepend and append strings to input

#     encoded_data = urllib.parse.quote(string, safe='') # URL encode ; and =

#     # padded_data = pad(encoded_data) # pad data
#     padded_data = pad(encoded_data.encode()) # pad data

#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     encrypted = cipher.encrypt(padded_data) # encrypt using AES-128-CBC

#     return encrypted


# def verify(ciphertext, key, iv):
#     cipher = AES.new(key, AES.MODE_CBC, iv)

#     decrypted_data = cipher.decrypt(ciphertext)
#     unpadded_data = unpad(decrypted_data)

#     # decoded = urllib.parse.unquote(unpadded_data)
#     decoded = urllib.parse.unquote(unpadded_data[16:].decode('utf-8'))

#     print(f"Decrypted data: {decoded}")

#     pattern = ";admin=true;"

#     return pattern in decoded


# def attack(ciphertext):
#     # convert ct to byte array
#     # cipher = AES.new(key, AES.MODE_CBC, iv)
#     modified_ciphertext = bytearray(ciphertext)

#     # modified_ciphertext[4] ^= ord('@') ^ ord(';')
#     modified_ciphertext[10] ^= ord('$') ^ ord('=')
#     # modified_ciphertext[15] ^= ord('*') ^ ord(';')

#     return bytes(modified_ciphertext)


# if __name__ == '__main__':
#     key = gen_key_iv()
#     iv = gen_key_iv()

#     ciphertext = submit("@admin$true*", key, iv)
#     print("Original Verify:", verify(ciphertext, key, iv))

#     # bit flipping attack
#     modified_ciphertext = attack(ciphertext)
#     # modified_ciphertext = tamper_ciphertext(ciphertext)

#     # verify tampered
#     is_admin = verify(modified_ciphertext, key, iv)

#     print(f"Second Verify after attack: {is_admin}")


# import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import urllib.parse


def gen_key_iv():
    return get_random_bytes(16)

# Generate a random AES key and IV
key = gen_key_iv()  # AES-128 requires a 16-byte key
iv = gen_key_iv()  # IV should also be 16 bytes

# Predefined strings for submission
pre = "userid=456;userdata="
post = ";session-id=31337"


def url_encoding(string):
    """URL encodes the given string, encoding ';' and '='."""
    return urllib.parse.quote(string, safe="")


def url_decoding(string):
    """URL decodes the given string."""
    return urllib.parse.unquote(string)


def encrypt_cbc(data, key, iv):
    """Encrypts the given data using AES in CBC mode."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))


def pkcs_unpadding(data):
    """Unpad data using PKCS#7 padding."""
    return unpad(data, AES.block_size)


def submit(user_str):
    """Prepares the string, encrypts it, and returns the ciphertext."""
    url_encoded_str = pre + url_encoding(user_str) + post  # Prepare final string
    print("submit() would create the string:", url_encoded_str)  # Debugging output
    res = encrypt_cbc(url_encoded_str, key, iv)  # Encrypt the string
    return res


def tamper_ciphertext(ciphertext):
    """Tamper with the ciphertext to inject the admin flag."""
    enc_list = bytearray(ciphertext)  # Convert to mutable bytearray
    # Modify specific bytes based on understanding of CBC operation
    enc_list[4] ^= ord("@") ^ ord(";")  # Change ';' to '@'
    enc_list[10] ^= ord("$") ^ ord("=")  # Change '=' to '$'
    enc_list[15] ^= ord("*") ^ ord(";")  # Change ';' to '*'
    return bytes(enc_list)  # Return modified ciphertext


def verify(ciphertext):
    """Decrypts the ciphertext, checks for the admin flag, and returns the result."""
    print("VERIFY", ciphertext)  # Debugging output
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher for decryption
    decrypted_data = pkcs_unpadding(cipher.decrypt(ciphertext))  # Decrypt and unpad
    decoded_data = url_decoding(decrypted_data[16:].decode("utf-8"))  # Decode URL
    print("ORIGINAL", decoded_data)  # Debugging output
    return ";admin=true;" in decoded_data  # Check for admin flag


# Example usage
user_input = "@admin$true*"
ciphertext = submit(user_input)

# Tamper with the ciphertext to inject admin flag
modified_ciphertext = tamper_ciphertext(ciphertext)

# Verify if the tampering worked
result = verify(modified_ciphertext)
print(
    "Verification result:", result
)  # Should print True if the tampering was successful
