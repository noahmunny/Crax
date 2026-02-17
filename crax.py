import hashlib
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor

# Hash algorithm lengths for common types
HASH_LENGTHS = {
    32: 'md5',
    40: 'sha1',
    64: 'sha256',
    128: 'sha512',
    56: 'sha224',
    96: 'sha384',
}

def detect_algorithm(target_hash):
    """Detects the hash algorithm based on the hash length"""
    hash_length = len(target_hash)
    if hash_length in HASH_LENGTHS:
        return HASH_LENGTHS[hash_length]
    else:
        print("Hash length not recognized. Please specify an algorithm.")
        return None

def crack_hash(word, algorithm, target_hash):
    """Cracks the hash using a given word and algorithm"""
    try:
        hash_func = hashlib.new(algorithm)
        hash_func.update(word.encode())
        test_hash = hash_func.hexdigest()
        if test_hash == target_hash:
            return word
    except Exception as e:
        print(f"Error: {e}")
    return None

def process_wordlist(wordlist, algorithm, target_hash):
    with open(wordlist, "r") as f:
        for i, word in enumerate(f):
            word = word.strip()

            hash_func = hashlib.new(algorithm)
            hash_func.update(word.encode())
            test_hash = hash_func.hexdigest()

            if test_hash == target_hash:
                print(f"Found: {word}")
                return

            if i % 50000 == 0:
                print(f"Tried {i} words...")

    print("No match found.")

def main():
    if len(sys.argv) < 3:
        print("Usage: python crack.py <hash> <wordlist> [<algorithm>]")
        sys.exit(1)

    target_hash = sys.argv[1].lower()
    wordlist = sys.argv[2]

    # Detect the algorithm if not specified
    algorithm = sys.argv[3].lower() if len(sys.argv) > 3 else detect_algorithm(target_hash)

    if not algorithm:
        sys.exit(1)

    if algorithm not in hashlib.algorithms_available:
        print(f"Unsupported algorithm: {algorithm}")
        sys.exit(1)

    print(f"Cracking hash using {algorithm}...")

    start_time = time.time()
    process_wordlist(wordlist, algorithm, target_hash)
    elapsed_time = time.time() - start_time

    print(f"Process completed in {elapsed_time:.2f} seconds.")

if __name__ == "__main__":
    main()

