"""
Shuffle a list in a way that does not require holding the list in memory.

Function ``shuffle_indices`` generates indices from 0 to size (exclusive)
in a deterministic random order based on the key bytes. These indices can
then be used for lookups into a list of the given length.

This is probably not a cryptographically secure process. Specifically
note that a number of iterations have to be skipped when the list
is not 2^(4 + x) elements long, which may reveal information. But there
are probably lots of other problems too!
"""

import hashlib
import math
import random

import string

def xor_bytes(xs, ys):
    return bytes(x ^ y for x, y in zip(xs, ys))

def random_key():
    letters = string.ascii_lowercase
    key = ''.join(random.choice(letters) for i in range(10))
    print(key)
    return key.encode();

def round_fn(block_size, piece, key):
    # 16: 8 bits per byte, and 2 because half the block size
    return hashlib.shake_128(piece + key).digest(block_size // 16) # XXX block size


def encrypt(plain_int, block_size, round_keys):
    plain_bytes = plain_int.to_bytes(block_size, byteorder='big')[-block_size // 8:] # XXX block size

    def run_round(left_i, right_i, round_key):
        left_next = right_i
        round_results = round_fn(block_size, right_i, round_key)
        right_next = xor_bytes(left_i, round_results)
        return (left_next, right_next)

    left = plain_bytes[:block_size // 16] # XXX block size
    right = plain_bytes[block_size // 16:] # XXX block size
    for round_key in round_keys:
        left, right = run_round(left, right, round_key)

    return int.from_bytes(right + left, byteorder='big')


def decrypt(plain_int, block_size, round_keys):
    """Decryption is just encryption with reversed round keys."""
    return encrypt(plain_int, block_size, list(reversed(round_keys)))


def encrypt_until_within_range(plain_int, block_size, round_keys, list_size): # XXX VERY not constant-time
    """
    Iteratively encrypt until the output is in [0, list_size).
    """
    current = plain_int
    while True:
        current = encrypt(current, block_size, round_keys)
        if current < list_size:
            return current


def decrypt_until_within_range(plain_int, block_size, round_keys, list_size):
    """Decryption is just encryption with reversed round keys."""
    return encrypt_until_within_range(plain_int, block_size, list(reversed(round_keys)), list_size)


def block_size_for(size):
    """
    Compute the needed block size for a list of the given length.
    """


    # Need a number of bits n where 2^n >= size and n divisible by
    # sixteen (two bytes, one for each side of the block.) This
    # results in needing to skip a large number of iterations to get
    # to the next index. This could be reduced heavily with sub-byte
    # bit-twiddling, although n still needs to be divisible by 2
    # because of the two halves of the cipher.
    block_size = math.ceil(math.log2(size))
    block_size += -block_size % 16 # XXX block size
    return block_size


def make_round_keys(block_size, key):
    """
    Given a block size and a key, yield a list of four round keys.
    """

    rounds = 4
    # Make one key piece for each round
    key_bits_per_round = block_size // 2
    key_bits = key_bits_per_round * rounds

    round_keys_raw = hashlib.shake_128(key).digest(key_bits)
    return [
        round_keys_raw[start:start+key_bits_per_round]
        for start in range(0, key_bits, key_bits_per_round)
    ]

def demo_shuffle_indices(size, key):
    """
    Yield a indices in a permutation based on key.
    """
    block_size = block_size_for(size)

    print (block_size);
    round_keys = make_round_keys(block_size, key)
    #print(round_keys);

    for i in range(0, size):
        enc = encrypt_until_within_range(i, block_size, round_keys, size)
        print(f"{i} -> {enc}")


def main():
    size = 42  # length of list we'll be traversing
    size = 16;
    key = random_key();

    print(f"A permutation of a list of {size} elements:")
    demo_shuffle_indices(size, key)
    print()


if __name__== '__main__':
    main()

