import hashlib
import sys
import time
import os

# Supported hash lengths
HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}


def detect_algorithm(target_hash):
    """Detect hash algorithm based on hash length."""
    algo = HASH_LENGTHS.get(len(target_hash))
    if not algo:
        print("[-] Unable to detect hash algorithm by length.")
    return algo


def crack_hash(target_hash, wordlist, algorithm):
    """Stream wordlist line-by-line and compare hashes."""
    attempts = 0
    start_time = time.time()

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                attempts += 1
                word = line.strip()

                hash_obj = hashlib.new(algorithm)
                hash_obj.update(word.encode())
                if hash_obj.hexdigest() == target_hash:
                    elapsed = time.time() - start_time
                    print(f"\n[+] Password found: {word}")
                    print(f"[+] Attempts: {attempts}")
                    print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                    return

                # Progress update every 50k attempts
                if attempts % 50000 == 0:
                    elapsed = time.time() - start_time
                    print(f"[*] Tried {attempts} passwords... ({elapsed:.1f}s elapsed)")

    except FileNotFoundError:
        print("[-] Wordlist file not found.")
        return

    elapsed = time.time() - start_time
    print("\n[-] No match found.")
    print(f"[*] Total attempts: {attempts}")
    print(f"[*] Time elapsed: {elapsed:.2f} seconds")


def main():
    if len(sys.argv) < 3:
        print("Usage: python crax.py <hash> <wordlist> [algorithm]")
        sys.exit(1)

    target_hash = sys.argv[1].lower()
    wordlist = sys.argv[2]

    # Manual algorithm override
    if len(sys.argv) == 4:
        algorithm = sys.argv[3].lower()
    else:
        algorithm = detect_algorithm(target_hash)

    if not algorithm:
        sys.exit(1)

    if algorithm not in hashlib.algorithms_available:
        print(f"[-] Unsupported algorithm: {algorithm}")
        sys.exit(1)

    print(f"[+] Using algorithm: {algorithm}")
    print(f"[+] Starting hash audit...\n")

    crack_hash(target_hash, wordlist, algorithm)


if __name__ == "__main__":
    main()
