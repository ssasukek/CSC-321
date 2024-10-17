from Crypto.Util.number import getPrime, inverse

# RSA key generation
def generatekeypair(bits):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    return ((n, e), (n, d))

# RSA encryption
def encrypt(m, publickey):
    n, e = publickey
    return pow(m, e, n)

# RSA decryption
def decrypt(ciphertext, privatekey):
    n, d = privatekey
    return pow(ciphertext, d, n)

# Mallory modifies the encrypted vote
def modify_vote(public_key, ciphertext, r):
    n, e = public_key
    r_e = pow(r, e, n)
    return (ciphertext * r_e) % n

def main():
    public_key, private_key = generatekeypair(2048)

    vote = 42 
    print(f"Alice's original vote (plaintext): {vote}")

    encrypted_vote = encrypt(vote, public_key)
    print(f"Encrypted vote: {encrypted_vote}")

    # Mallory intercepts and modifies the encrypted vote
    r = 2
    modified_vote = modify_vote(public_key, encrypted_vote, r)
    print(f"Modified encrypted vote: {modified_vote}")

    decrypted_modified_vote = decrypt(modified_vote, private_key)
    print(f"Decrypted modified vote (plaintext): {decrypted_modified_vote}")

    print(f"Expected modified vote (original vote * r): {vote * r}")

if __name__ == "__main__":
    main()
