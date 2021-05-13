var Util = require("cryptomancy-util");
var Format = require("cryptomancy-format");
var Nacl = require("tweetnacl");

// https://www.brainonfire.net/blog/2021/05/06/cryptographic-shuffle/
/*  Shuffle a list in a way that does not require holding the list in memory.

    Function ``shuffle_indices`` generates indices from 0 to size (exclusive)
    in a deterministic random order based on the key bytes. These indices can
    then be used for lookups into a list of the given length.

    This is probably not a cryptographically secure process. Specifically
    note that a number of iterations have to be skipped when the list
    is not 2^(4 + x) elements long, which may reveal information. But there
    are probably lots of other problems too!
*/

var Bij = module.exports;

/*
def round_fn(block_size, piece, key):
    # 16: 8 bits per byte, and 2 because half the block size
    return hashlib.shake_128(piece + key).digest(block_size // 16)
*/
var round_fn = Bij.round_fn = function (block_size, piece, key) {
    // 16: 8 bits per byte, and 2 because half the block size
    return Util.slice(Nacl.hash(Util.concat([piece, key])), 0, Math.floor(block_size / 16));
};

var encrypt = Bij.encrypt = function (u8_bytes /*plain_int*/, block_size, round_keys) {
    var run_round = function (left_i, right_i, round_key) {
        var left_next = right_i;
        var round_results = round_fn(block_size, right_i, round_key);
        var right_next = Util.xor.array(left_i, round_results);
        return [
            left_next,
            right_next
        ];
    };
    var len = u8_bytes.length;
    var split = Math.floor((len * 8) / 16);
    var left = Util.slice(u8_bytes, 0, split);
    var right = Util.slice(u8_bytes, split);

    round_keys.forEach(function (round_key) {
        var result = run_round(left, right, round_key);
        left = result[0];
        right = result[1];
    });

    return Util.concat([right, left]);
};

// Decryption is just encryption with reversed round keys.
var decrypt = Bij.decrypt = function (u8_bytes /* plain_int */, block_size, round_keys) {
    return encrypt(u8_bytes /* plain_int */, block_size, round_keys.reverse());
};

var inRange = Bij.inRange = function (u8, max) {
    var n = Number(Format.encodeBigInt(u8).toString());
    return n < max;
};

var to_int = Bij.to_int = function (u8) { // only handles {1..256}
    return (u8[0] << 8) | u8[1];
};

// Iteratively encrypt until the output is in [0, list_size).
var encrypt_until_within_range = Bij.encrypt_until_within_range = function (plain_int, block_size, round_keys, list_size) {
    var enc = new Uint8Array([0, plain_int]); // encode as Uint8Array
    for (;;) {
        enc = Bij.encrypt(enc, block_size, round_keys, list_size);
        if (to_int(enc) < list_size) { return enc; }
    }
};

// Decryption is just encryption with reversed round keys.
var decrypt_until_within_range = Bij.decrypt_until_within_range = function (plain_int, block_size, round_keys, list_size) {
    return encrypt_until_within_range(plain_int, block_size, round_keys.reverse(), list_size);
};

var python_mod = function (x, y) {
    return x >= 0? x % y: y - (-x % y);
};

// Compute the needed block size for a list of the given length.
// Need a number of bits n where 2^n >= size and n divisible by
// sixteen (two bytes, one for each side of the block.) This
// results in needing to skip a large number of iterations to get
// to the next index. This could be reduced heavily with sub-byte
// bit-twiddling, although n still needs to be divisible by 2
// because of the two halves of the cipher.
var block_size_for = Bij.block_size_for = function (size) {
    var block_size = Math.ceil(Math.log2(size));
    block_size += python_mod(-block_size, 16); // XXX
    return block_size;
};

// Given a block size and a key, yield a list of four round keys.
var Source = require("cryptomancy-source");
var make_round_keys = Bij.make_round_keys = function (block_size, key) {
    var rounds = 4;
    // Make one key piece for each round
    var key_bits_per_round = Math.floor(block_size / 2);
    var key_bits = key_bits_per_round * rounds;

    var key_stream = Source.bytes.deterministic(key);
    return range(0, 4).map(function () {
        return key_stream(key_bits_per_round / 8);
    });
};

var range = Bij.range = function (start, stop) {
    var A = [];
    while (start < stop) {
        A.push(start);
        start++;
    }
    return A;
};

// Yield a indices in a permutation based on key.
var demo_shuffle_indices = Bij.demo_shuffle_indices = function (size, key) { // XXX
    var block_size = block_size_for(size);
    var round_keys = make_round_keys(block_size, key);
    range(0, 16 /* size */).forEach(function (i) {
        var enc = encrypt_until_within_range(new Uint8Array([0, 0, 0, i]), block_size, round_keys, size);
    });
};

Bij.make_key = function (s) {
    return Format.decodeUTF8(s);
};

