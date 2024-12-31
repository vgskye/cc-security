package vg.skye;

import dan200.computercraft.api.lua.IComputerSystem;
import dan200.computercraft.api.lua.ILuaAPI;
import dan200.computercraft.api.lua.LuaFunction;
import dan200.computercraft.core.apis.ComputerAccess;
import dan200.computercraft.core.filesystem.FileSystem;
import dan200.computercraft.core.filesystem.FileSystemException;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import vg.skye.mixin.ComputerSystemAccessor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static vg.skye.CryptoApi.fromBytes;

public class AuditApi implements ILuaAPI {
    private static byte[] traverseHash(FileSystem fs, String path) throws FileSystemException, IOException {
        if (!fs.exists(path)) {
            throw new IllegalArgumentException("Nonexistent path!");
        }
        if (!fs.isDir(path)) {
            var fd = fs.openForRead(path);
            var file = fd.get();
            var contents = ByteBuffer.allocate((int) file.size());
            file.read(contents);
            fd.close();
            var digest = new Blake2sDigest("file".getBytes(StandardCharsets.UTF_8));
            digest.update(contents.array(), 0, contents.array().length);
            var result = new byte[32];
            digest.doFinal(result, 0);
            return result;
        }
        var tree = new StringBuilder();
        for (String entry : fs.list(path)) {
            tree.append(entry);
            tree.append("\t");
            var hashed = traverseHash(fs, path + "/" + entry);
            tree.append(HexFormat.of().formatHex(hashed));
            tree.append("\n");
        }
        var treeBytes = tree.toString().getBytes(StandardCharsets.UTF_8);
        var digest = new Blake2sDigest("dir".getBytes(StandardCharsets.UTF_8));
        digest.update(treeBytes, 0, treeBytes.length);
        var result = new byte[32];
        digest.doFinal(result, 0);
        return result;
    }

    private final ComputerAccess computer;
    private final byte[] sigKey;

    public static AuditApi of(IComputerSystem computer) {
        if (computer instanceof ComputerAccess computerSystem) {
            return new AuditApi(computerSystem);
        }
        return null;
    }

    AuditApi(ComputerAccess computer) {
        this.computer = computer;
        sigKey = CCSecurity.KEY_MATERIAL.derive("audit".getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String[] getNames() {
        return new String[]{ "audit" };
    }

    @LuaFunction
    public final String pubkey() {
        var key = new Ed25519PrivateKeyParameters(sigKey);
        return fromBytes(key.generatePublicKey().getEncoded());
    }

    @LuaFunction
    public final String[] generateAuditReport(String nonce) {
        try {
            var env = ((ComputerSystemAccessor) computer).getEnvironment();
            var fs = env.getFileSystem();
            var id = computer.getID();
            var fsHash = traverseHash(fs, "");
            var fsDigest = HexFormat.of().formatHex(fsHash);
            var toSign = String.format("%s\t%d\t%s", nonce, id, fsDigest);
            var toSignBytes = toSign.getBytes(StandardCharsets.UTF_8);
            var key = new Ed25519PrivateKeyParameters(sigKey);
            var signer = new Ed25519Signer();
            signer.init(true, key);
            signer.update(toSignBytes, 0, toSignBytes.length);
            return new String[]{toSign, fromBytes(signer.generateSignature())};
        } catch (FileSystemException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @LuaFunction
    public final String getDirectoryDigest(String path) {
        try {
            var env = ((ComputerSystemAccessor) computer).getEnvironment();
            var fs = env.getFileSystem();
            var fsHash = traverseHash(fs, path);
            return HexFormat.of().formatHex(fsHash);
        } catch (FileSystemException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
