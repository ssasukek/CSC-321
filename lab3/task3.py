from Crypto.Util.number import getPrime

def generate_prime(bits):
    return getPrime(bits)

def mod_inverse(a, m):
    """Compute the modular multiplicative inverse of a modulo m."""
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m
    
# Requirement: Implement key generation
def generate_keypair(bits):
    """Generate RSA public and private keys."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Requirement: Use the value e=65537
    d = mod_inverse(e, phi)
    d_check = pow(e, -1, phi)
    #print(f"\nmod_inverse_check (d): {d}")
    #print(f"pow (d_check): {d_check}\n")
    return ((n, e), (n, d))

# encrypt using public key
def encrypt(msg, public_key):
    # RSA encryption: c = m^e mod n
    n, e = public_key
    m = string_to_int(msg)
    c = pow(m, e, n)
    return c

# decrypt using private key
def decrypt(ciphertext, private_key):
    # RSA decryption: m^d mod n
    n, d = private_key
    m = pow(ciphertext, d, n)
    return int_to_string(m)

# convert a str into an int
def string_to_int(msg):
    return int.from_bytes(msg.encode(), byteorder='big')

# convert an int back to str
def int_to_string(m):
    return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode()

def test_rsa():
    public_key, private_key = generate_keypair(2048)

    msg = "Hello, RSA!"

    ciphertext = encrypt(msg, public_key)
    print(ciphertext)

    decrypt_msg = decrypt(ciphertext, private_key)
    print(decrypt_msg)




if __name__ == "__main__":
    test_rsa()  