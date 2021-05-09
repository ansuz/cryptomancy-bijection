var Util = require("cryptomancy-util");
var Format = require("cryptomancy-format");
var Nacl = require("tweetnacl");

// https://www.brainonfire.net/blog/2021/05/06/cryptographic-shuffle/

/*
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

def xor_bytes(xs, ys):
    return bytes(x ^ y for x, y in zip(xs, ys))


def round_fn(block_size, piece, key):
    # 16: 8 bits per byte, and 2 because half the block size
    return hashlib.shake_128(piece + key).digest(block_size // 16)


*/

var round = function (block_size, piece, key) {
    // 16: 8 bits per byte, and 2 because half the block size
    return Util.slice(Nacl.hash(Util.concat([piece, key])), 0, block_size / 2);
};


/*

def encrypt(plain_int, block_size, round_keys):
    plain_bytes = plain_int.to_bytes(block_size, byteorder='big')[-block_size // 8:]

    def run_round(left_i, right_i, round_key):
        left_next = right_i
        round_results = round_fn(block_size, right_i, round_key)
        right_next = xor_bytes(left_i, round_results)
        return (left_next, right_next)

    left = plain_bytes[:block_size // 16]
    right = plain_bytes[block_size // 16:]
    for round_key in round_keys:
        left, right = run_round(left, right, round_key)

    return int.from_bytes(right + left, byteorder='big')

*/

var encrypt = function (plain_int, block_size, round_keys) {


};



/*


def decrypt(plain_int, block_size, round_keys):
    """Decryption is just encryption with reversed round keys."""
    return encrypt(plain_int, block_size, list(reversed(round_keys)))

*/

var decrypt = function (plain_int, block_size, round_keys) {


};


/*


def encrypt_until_within_range(plain_int, block_size, round_keys, list_size):
    """
    Iteratively encrypt until the output is in [0, list_size).
    """
    current = plain_int
    while True:
        current = encrypt(current, block_size, round_keys)
        if current < list_size:
            return current

*/


var encrypt_until_within_range = function (plain_int, block_size, round_keys, list_size) {



};


/*


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
    block_size += -block_size % 16
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


def demo_reversible(size, start, key):
    block_size = block_size_for(size)
    round_keys = make_round_keys(block_size, key)

    print("Demo of encryption and decryption:")
    enc = encrypt(start, block_size, round_keys)
    dec = decrypt(enc, block_size, round_keys)
    print(f"Encrypted {start} to {enc}, then decrypted back to {dec}")


def demo_shuffle_indices(size, key):
    """
    Yield a indices in a permutation based on key.
    """
    block_size = block_size_for(size)
    round_keys = make_round_keys(block_size, key)

    for i in range(0, size):
        enc = encrypt_until_within_range(i, block_size, round_keys, size)
        print(f"{i} -> {enc}")


def shuffled_hop(size, start, key):
    """
    Given a starting index in the permuted list, what's the next index?
    """
    block_size = block_size_for(size)
    round_keys = make_round_keys(block_size, key)

    # Decrypt, increment, encrypt
    plain = decrypt_until_within_range(start, block_size, round_keys, size)
    return encrypt_until_within_range(plain + 1, block_size, round_keys, size)


def main():
    size = 42  # length of list we'll be traversing
    key = "some random seed".encode()

    demo_reversible(size, 17, key)
    print()

    print(f"To permute a list of length {size} this implementation needs a "
          f"block size of {block_size_for(size)} bits.")
    print()

    print(f"A permutation of a list of {size} elements:")
    demo_shuffle_indices(size, key)
    print()

    start = 10
    print(f"Starting at {start}, what's the next index in this traversal?")
    print(shuffled_hop(size, start, key))


if __name__== '__main__':
    main()


*/




