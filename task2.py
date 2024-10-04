from Crypto.Cipher import AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
# from Crypto.Util.Padding import pad, unpad # type: ignore

def submit():
    # input: Arbitrary user string
    prepend_str = "userid=456;userdata="
    append_str = ";session-id=31337"

    # URL encode(convert) user input

    # Apply PKCS#7 padding

    # Encrypt using AES-128-CBC

    # output: Ciphertext

def verify():
    return