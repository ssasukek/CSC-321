from Crypto.Util.number import getPrime, inverse
from hashlib import sha256

# RSA key generation
def generate_keypair(bits):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    return ((n, e), (n, d))

# RSA signing: Sign the message with the private key
def sign(m, private_key):
    n, d = private_key
    return pow(m, d, n)

# RSA verification: Verify the signature with the public key
def verify(signature, message, public_key):
    n, e = public_key
    return pow(signature, e, n) == message

# Convert string to int
def string_to_int(msg):
    return int.from_bytes(msg.encode(), 'big')

# Convert int to string
def int_to_string(m):
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

# Mallory forges a new signature
def signature_forgery(public_key, signature, r, private_key):
    n, d = private_key
    r_d = pow(r, d, n)
    forged_signature = (signature * r_d) % n
    return forged_signature

def main():
    # Key generation for Alice
    public_key, private_key = generate_keypair(2048)

    # Message 1 from Alice
    msg1 = "Pay 100 dollars"
    m1 = string_to_int(msg1)
    signature1 = sign(m1, private_key)

    # Message 2 from Alice
    msg2 = "Pay 500 dollars"
    m2 = string_to_int(msg2)
    signature2 = sign(m2, private_key)

    # Mallory forges a new signature
    m3 = m1 * m2
    signature3 = signature1 * signature2
    test = verify(signature3, m3, public_key)
    print(f"Verify signature: {test}")

if __name__ == "__main__":
    main()