from hashlib import sha256
import random
import string
import matplotlib.pyplot as plt
import time

# part 1
def sha256_hash(input_str):
    # Convert input_string to bytes
    input_bytes = input_str.encode('utf-8')
    # Calculate SHA256 hash of the bytes
    hash_obj = sha256(input_bytes)
    # Return the hash as a hexadecimal string
    return hash_obj.hexdigest()

# part 2
def hamming_distance(s1, s2):
    count = 0
    # FOR each pair of characters (c1, c2) in (s1, s2):
    for c1, c2 in zip(s1, s2):
        if c1 != c2:
            count += 1
    return count

# part 3
def truncate_hash(hash_str, bits):
    """Take the first (bits / 4) characters of hash_string
    Convert this substring to an integer (base 16)
    Create a bitmask of 'bits' number of 1s
    Perform bitwise AND between the integer and the bitmask"""
    hex_len = bits // 4
    truncate_hex = hash_str[:hex_len]
    return int(truncate_hex, 16) & ((1 << bits) - 1)

def find_collision(bits, max_attempts):
    # Initialize empty dictionary 'seen'
    seen = {}
    for attempts in range(max_attempts):
        # generate random string s of 10 ascii letters
        s = ''.join(random.choices(string.ascii_letters, k = 10))
        # truncated h
        h = truncate_hash(sha256_hash(s), bits)
        if h in seen:
            return seen[h], s, attempts
        seen[h] = s
    return None, None, max_attempts

def task_1a():
    print("Task 1a: SHA256 shashes of arbitrary inputs")
    lst = ["Hello, World!", "Python", "Cryptography"]
    for input in lst:
        hash_val = sha256_hash(input)
        print(f"Input: {input}\nHash: {hash_val}\n")

def task_1b():
    print("Task 1b: Strings with Hamming distance of 1")
    s1 = ["Hello", "Python", "Cryptography"]
    s2 = ["Hellp", "Pythoo", "Cryptographz"]
    for i in range(3):
        string1, string2 = s1[i], s2[i]
        h1, h2 = sha256_hash(string1), sha256_hash(string2)
        print(string1, string2, h1, h2)

def task_1c():
    print("Task 1c: Finding collisions for truncated hashes")
    bits_lst = []
    time_lst = []
    input_lst = []

    for bits in range(8,50,2):
        print(f"Finding collision for {bits} number of bits")
        start_time = time.time()
        s1, s2, attempts = find_collision(bits, 1000000000)
        end_time = time.time()
        if s1 and s2:
            print(f"Collision found at attempt: {attempts}")
            bits_lst.append(bits)
            time_lst.append(end_time - start_time)
            input_lst.append(attempts)
            print(f"Time taken: {end_time - start_time} seconds")
        else:
            print(f"Timeout: no collision found for {bits} bits")

    plt.plot(bits_lst, time_lst)
    plt.xlabel('Digest Size (bits)')
    plt.ylabel('Time Taken (s)')
    plt.title('Total Time for Collision Detection')
    plt.grid(True)
    plt.savefig('collision_time.png')

    plt.clf()

    plt.plot(bits_lst, input_lst)
    plt.xlabel('Digest Size (bits)')
    plt.ylabel('Number of Attempts')
    plt.title('Number of Attempts for Collision Detection')
    plt.grid(True)
    plt.savefig('collision_attempts.png')

    
if __name__ == "__main__":
    task_1a()
    task_1b()
    task_1c()