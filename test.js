var Bij = require(".");

var test = function () {
    var list_size = 256;
    var key = Bij.make_key('pewpewpew');
    var block_size = Bij.block_size_for(list_size);
    var round_keys = Bij.make_round_keys(block_size, key);
    Bij.range(0, list_size).forEach(function (n) {
        console.log("%s => %s", n, Bij.to_int(Bij.encrypt_until_within_range(n, block_size, round_keys, list_size)));
    });
};

test();
