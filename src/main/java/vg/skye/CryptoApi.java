package vg.skye;

import dan200.computercraft.api.lua.IComputerSystem;
import dan200.computercraft.api.lua.ILuaAPI;
import dan200.computercraft.api.lua.LuaFunction;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.math.ec.rfc7748.X25519;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;

public class CryptoApi implements ILuaAPI {
    private static boolean isValidPrivkey(byte[] key) {
        return (key[0] & 0b00000111) == 0 &&
                (key[31] & 0b10000000) == 0 &&
                (key[31] & 0b01000000) == 0b01000000;
    }

    private final byte[] sigKey;
    private final byte[] dhKey;

    CryptoApi(IComputerSystem computer) {
        var key = CCSecurity.KEY_MATERIAL;
        var id = computer.getID();
        sigKey = key.derive(String.format("%d_sig", id).getBytes(StandardCharsets.UTF_8));
        var dhKeySeed = key.derive(String.format("%d_dh", id).getBytes(StandardCharsets.UTF_8));
        dhKeySeed[0] &= 0xF8;
        dhKeySeed[X25519.SCALAR_SIZE - 1] &= 0x7F;
        dhKeySeed[X25519.SCALAR_SIZE - 1] |= 0x40;
        dhKey = dhKeySeed;
    }

    @Override
    public String[] getNames() {
        return new String[]{ "crypto" };
    }

    public static byte[] toBytes(String string) {
        var chars = new byte[string.length()];
        for (var i = 0; i < chars.length; i++) {
            var c = string.charAt(i);
            chars[i] = c < 256 ? (byte) c : 63;
        }

        return chars;
    }

    public static String fromBytes(byte[] bytes) {
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i] = ((char) (bytes[i] & 0xFF));
        }
        return String.valueOf(chars);
    }

    @LuaFunction
    public final String randBytes(int length) {
        var rand = new SecureRandom();
        var result = new byte[length];
        rand.nextBytes(result);
        return fromBytes(result);
    }

    @LuaFunction
    public final String sha256(String data) {
        var dataBytes = toBytes(data);
        var digest = new SHA256Digest();
        digest.update(dataBytes, 0, dataBytes.length);
        var result = new byte[32];
        digest.doFinal(result, 0);
        return fromBytes(result);
    }

    @LuaFunction
    public final String sha384(String data) {
        var dataBytes = toBytes(data);
        var digest = new SHA384Digest();
        digest.update(dataBytes, 0, dataBytes.length);
        var result = new byte[48];
        digest.doFinal(result, 0);
        return fromBytes(result);
    }

    @LuaFunction
    public final String sha512(String data) {
        var dataBytes = toBytes(data);
        var digest = new SHA512Digest();
        digest.update(dataBytes, 0, dataBytes.length);
        var result = new byte[64];
        digest.doFinal(result, 0);
        return fromBytes(result);
    }

    @LuaFunction
    public final String blake2s(String data, Optional<String> key) {
        var dataBytes = toBytes(data);
        var digest = key.map(CryptoApi::toBytes).map(Blake2sDigest::new).orElseGet(Blake2sDigest::new);
        digest.update(dataBytes, 0, dataBytes.length);
        var result = new byte[32];
        digest.doFinal(result, 0);
        return fromBytes(result);
    }

    @LuaFunction
    public final String blake2b(String data, Optional<String> key) {
        var dataBytes = toBytes(data);
        var digest = key.map(CryptoApi::toBytes).map(Blake2bDigest::new).orElseGet(Blake2bDigest::new);
        digest.update(dataBytes, 0, dataBytes.length);
        var result = new byte[64];
        digest.doFinal(result, 0);
        return fromBytes(result);
    }

    @LuaFunction
    public final String sigPrivkey() {
        var key = new Ed25519PrivateKeyParameters(new SecureRandom());
        return fromBytes(key.getEncoded());
    }

    @LuaFunction
    public final String sigPubkey(Optional<String> privkey) {
        var keyBytes = privkey.map(CryptoApi::toBytes).orElse(sigKey);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("invalid private key length");
        }
        var key = new Ed25519PrivateKeyParameters(keyBytes);
        return fromBytes(key.generatePublicKey().getEncoded());
    }

    @LuaFunction
    public final String sign(String data, Optional<String> privkey) {
        var dataBytes = toBytes(data);
        var keyBytes = privkey.map(CryptoApi::toBytes).orElse(sigKey);
        var key = new Ed25519PrivateKeyParameters(keyBytes);
        var signer = new Ed25519Signer();
        signer.init(true, key);
        signer.update(dataBytes, 0, dataBytes.length);
        return fromBytes(signer.generateSignature());
    }

    @LuaFunction
    public final boolean verify(String data, String pubkey, String signature) {
        var dataBytes = toBytes(data);
        var keyBytes = toBytes(pubkey);
        var sigBytes = toBytes(signature);
        var key = new Ed25519PublicKeyParameters(keyBytes);
        var signer = new Ed25519Signer();
        signer.init(false, key);
        signer.update(dataBytes, 0, dataBytes.length);
        return signer.verifySignature(sigBytes);
    }

    @LuaFunction
    public final String dhPrivkey() {
        var output = new byte[32];
        X25519.generatePrivateKey(new SecureRandom(), output);
        return fromBytes(output);
    }

    @LuaFunction
    public final String dhPubkey(Optional<String> privkey) {
        var keyBytes = privkey.map(CryptoApi::toBytes).orElse(dhKey);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("invalid private key length");
        }
        if (!isValidPrivkey(keyBytes)) {
            throw new IllegalArgumentException("invalid private key");
        }
        var output = new byte[32];
        X25519.generatePublicKey(keyBytes, 0, output, 0);
        return fromBytes(output);
    }

    @LuaFunction
    public final String agree(String pubkey, Optional<String> privkey) {
        var privkeyBytes = privkey.map(CryptoApi::toBytes).orElse(dhKey);
        var pubkeyBytes = toBytes(pubkey);
        if (privkeyBytes.length != 32) {
            throw new IllegalArgumentException("invalid private key length");
        }
        if (!isValidPrivkey(privkeyBytes)) {
            throw new IllegalArgumentException("invalid private key");
        }
        if (pubkeyBytes.length != 32) {
            throw new IllegalArgumentException("invalid public key length");
        }
        var result = new byte[32];
        X25519.calculateAgreement(privkeyBytes, 0, pubkeyBytes, 0, result, 0);
        return fromBytes(result);
    }

    @LuaFunction
    public final String encrypt(String data, String key, String nonce, Optional<String> aad) {
        var dataBytes = toBytes(data);
        var keyBytes = toBytes(key);
        var nonceBytes = toBytes(nonce);
        var aadBytes = aad.map(CryptoApi::toBytes).orElse(new byte[0]);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("invalid key length");
        }
        if (nonceBytes.length != 12) {
            throw new IllegalArgumentException("invalid nonce length");
        }
        var cipher = new ChaCha20Poly1305();
        cipher.init(true, new AEADParameters(new KeyParameter(keyBytes), 128, nonceBytes));
        cipher.processAADBytes(aadBytes, 0, aadBytes.length);
        var output = new byte[dataBytes.length + 16];
        var off = cipher.processBytes(dataBytes, 0, dataBytes.length, output, 0);
        try {
            cipher.doFinal(output, off);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
        return fromBytes(output);
    }

    @LuaFunction
    public final String decrypt(String data, String key, String nonce, Optional<String> aad) {
        var dataBytes = toBytes(data);
        var keyBytes = toBytes(key);
        var nonceBytes = toBytes(nonce);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("invalid key length");
        }
        if (nonceBytes.length != 12) {
            throw new IllegalArgumentException("invalid nonce length");
        }
        if (dataBytes.length < 16) {
            throw new IllegalArgumentException("ciphertext too short");
        }
        var aadBytes = aad.map(CryptoApi::toBytes).orElse(new byte[0]);
        var cipher = new ChaCha20Poly1305();
        cipher.init(false, new AEADParameters(new KeyParameter(keyBytes), 128, nonceBytes));
        cipher.processAADBytes(aadBytes, 0, aadBytes.length);
        var output = new byte[dataBytes.length - 16];
        var off = cipher.processBytes(dataBytes, 0, dataBytes.length, output, 0);
        try {
            cipher.doFinal(output, off);
            return fromBytes(output);
        } catch (InvalidCipherTextException e) {
            return null;
        }
    }
}
