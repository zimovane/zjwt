const std = @import("std");
const utils = @import("./utils.zig");
const Err = std.crypto.errors;

const RSA = std.crypto.Certificate.rsa;
const HMAC = std.crypto.auth.hmac;
const Ecdsa = std.crypto.sign.ecdsa;
const Ed25519 = std.crypto.sign.Ed25519;

pub const HMACAlgorithm = enum {
    const Self = @This();
    HS256,
    HS384,
    HS512,

    fn sha2(comptime self: Self) type {
        return switch (self) {
            .HS256 => HMAC.sha2.HmacSha256,
            .HS384 => HMAC.sha2.HmacSha384,
            .HS512 => HMAC.sha2.HmacSha512,
        };
    }

    pub fn verify(comptime self: Self, sig_bytes: []const u8, msg: []const u8, key: []const u8) Err.SignatureVerificationError!void {
        const sig = self.sign(msg, key);
        if (utils.compareSlices(u8, sig_bytes, &sig)) {
            return Err.SignatureVerificationError.SignatureVerificationFailed;
        }
        return;
    }

    pub fn sign(comptime self: Self, msg: []const u8, key: []const u8) [self.sha2().mac_length]u8 {
        const alg = self.sha2();
        var out: [alg.mac_length]u8 = undefined;
        var hmac = alg.init(key);
        hmac.update(msg);
        hmac.final(&out);
        return out;
    }
};

pub const EcdsaAlgorithm = enum {
    const Self = @This();
    ES256,
    ES384,

    fn ecdsa(comptime self: Self) type {
        return switch (self) {
            .ES256 => Ecdsa.EcdsaP256Sha256,
            .ES384 => Ecdsa.EcdsaP384Sha384,
        };
    }

    pub fn verify(comptime self: Self, sig_bytes: []const u8, msg: []const u8, pbkey_bytes: []const u8) (Err.IdentityElementError || Err.NonCanonicalError || Err.SignatureVerificationError)!void {
        const alg = self.ecdsa();
        const sig = alg.Signature.fromBytes(sig_bytes);
        const pbkey = alg.PublicKey.fromSec1(pbkey_bytes);
        const verifier = try sig.verifier(pbkey);
        verifier.update(msg);
        return verifier.verify();
    }
};

pub const RSAAlgorithm = enum {
    const Self = @This();
    RS256,
    RS384,
    RS512,
    pub fn verify(_: Self, sig_bytes: []u8, msg: []const u8, pbkey_bytes: []u8) void {
        _ = pbkey_bytes;
        _ = msg;
        _ = sig_bytes;
    }
};

pub const Ed25519Algorithm = enum {
    const Self = @This();
    EdDSA,
    pub fn verify(comptime _: Self, sig_bytes: []const u8, msg: []const u8, pbkey_bytes: []const u8) (Err.SignatureVerificationError || Err.IdentityElementError || Err.WeakPublicKeyError || Err.EncodingError || Err.NonCanonicalError)!void {
        const sig = Ed25519.Signature.fromBytes(sig_bytes);
        const pbkey = try Ed25519.Publickey.fromBytes(pbkey_bytes);
        const verifier = try sig.verifier(pbkey);
        verifier.update(msg);
        return verifier.verify();
    }
};

test "hmac sign" {
    var out = HMACAlgorithm.HS256.sign("", "");
    try utils.assertEqual("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", out[0..]);

    out = HMACAlgorithm.HS256.sign("The quick brown fox jumps over the lazy dog", "key");
    try utils.assertEqual("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", out[0..]);
}

test "hmac verify" {
    const msg = "The quick brown fox jumps over the lazy dog";
    const key = "key";
    const sig = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";
    const sig_bytes = utils.hexToBytes(sig);
    const result = HMACAlgorithm.HS256.verify(sig_bytes, msg, key) catch unreachable;
    try std.testing.expectEqual(true, @TypeOf(result) == void);
}
