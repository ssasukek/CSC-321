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
def decrypt(c, privatekey):
    n, d = privatekey
    return pow(c, d, n)

# Mallory modifies the encrypted vote
def modify_vote(public_key, c, r):
    n, e = public_key
    r_e = pow(r, e, n)
    return (c * r_e) % n

def main():
    # Generate keypair for the voting authority
    public_key, private_key = generatekeypair(2048)

    # Alice's vote (candidate number)
    vote = 42  # Let's assume Alice voted for candidate 42
    print(f"Alice's original vote (plaintext): {vote}")

    # Alice encrypts her vote using the public key
    encrypted_vote = encrypt(vote, public_key)
    print(f"Encrypted vote: {encrypted_vote}")

    # Mallory intercepts and modifies the encrypted vote
    r = 2  # Mallory picks a random value for r
    modified_vote = modify_vote(public_key, encrypted_vote, r)
    print(f"Modified encrypted vote: {modified_vote}")

    # The voting authority decrypts the modified vote
    decrypted_modified_vote = decrypt(modified_vote, private_key)
    print(f"Decrypted modified vote (plaintext): {decrypted_modified_vote}")

    # The decrypted vote corresponds to Alice's original vote multiplied by r
    print(f"Expected modified vote (original vote * r): {vote * r}")

if __name__ == "__main__":
    main()
