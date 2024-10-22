import bcrypt
import time
import nltk
from nltk.corpus import words
from multiprocessing import Pool

nltk.download('words')

word_lst = [word for word in words.words() if 6 <= len(word) <= 10]

def read_file(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

def crack_password(entry):
    username, bcrypt_hash = entry.split(":")
    bcrypt_hash = bcrypt_hash.strip()
    startTime = time.time()
    count = 0

    for word in word_lst:
        count += 1
        word_byte = word.encode('utf-8')

        if count % 10000 == 0:
            print(f"{username} tried {count} passwords")

        if bcrypt.checkpw(word_byte, bcrypt_hash.encode('utf-8')):
            endTime = time.time()
            dur = endTime - startTime
            print(f"Password for {username} is {word} (found in {dur:.2f} sec, {count} attempts)")
            return
    return f"Password for {username} not found"

if __name__ == "__main__":
    entries = read_file("shadow.txt")
    with Pool() as pool:
        result = pool.map(crack_password, entries)

    for r in result:
        print(r)