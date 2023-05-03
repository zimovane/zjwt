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

    fn sha2(self: Self) HMAC.Hmac {
        switch (self) {
            .HS256 => HMAC.sha2.HmacSha256,
            .HS384 => HMAC.sha2.HmacSha384,
            .HS512 => HMAC.sha2.HmacSha512,
        }
    }

    pub fn verify(self: Self, sig_bytes: []u8, msg: []const u8, key: []u8) !void {
        const sig = self.sign(msg, key);
        if (!utils.compareSlices(u8, sig_bytes, sig)) {
            return Err.SignatureVerificationError;
        }
    }

    pub fn sign(self: Self, msg: []const u8, key: []const u8) [self.sha2().mac_length]u8 {
        const alg = self.sha2();
        var out: [alg.mac_length]u8 = undefined;
        const hmac = alg.init(key);
        hmac.update(msg);
        hmac.final(out);
        return out;
    }
};

pub const EcdsaAlgorithm = enum {
    const Self = @This();
    ES256,
    ES384,

    fn ecdsa(self: Self) Ecdsa {
        switch (self) {
            .ES256 => Ecdsa.EcdsaP256Sha256,
            .ES384 => Ecdsa.EcdsaP384Sha384,
        }
    }

    pub fn verify(self: Self, sig_bytes: []u8, msg: []const u8, pbkey_bytes: []u8) (Err.IdentityElementError || Err.NonCanonicalError || Err.SignatureVerificationError)!void {
        const alg = self.ecdsa();
        const sig = alg.Signature.fromBytes(sig_bytes);
        const pbkey = alg.PublicKey.fromSec1(pbkey_bytes);
        const verifier = try sig.verifier(pbkey);
        verifier.update(msg);
        verifier.verify();
    }
};

pub const RSAAlgorithm = enum {
    const Self = @This();
    RS256,
    RS384,
    RS512,
    pub fn verify(_: Self, sig_bytes: [64]u8, msg: []const u8, pbkey_bytes: [64]u8) void {
        _ = pbkey_bytes;
        _ = msg;
        _ = sig_bytes;
    }
};

pub const Ed25519Algorithm = enum {
    const Self = @This();
    EdDSA,
    pub fn verify(_: Self, sig_bytes: [64]u8, msg: []const u8, pbkey_bytes: [64]u8) (Err.SignatureVerificationError || Err.IdentityElementError || Err.WeakPublicKeyError || Err.EncodingError || Err.NonCanonicalError)!void {
        const sig = Ed25519.Signature.fromBytes(sig_bytes);
        const pbkey = try Ed25519.Publickey.fromBytes(pbkey_bytes);
        const verifier = try sig.verifier(pbkey);
        verifier.update(msg);
        verifier.verify();
    }
};
