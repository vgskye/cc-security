package vg.skye;

import net.minecraft.nbt.CompoundTag;
import net.minecraft.world.level.saveddata.SavedData;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.jetbrains.annotations.NotNull;

import java.security.SecureRandom;

public class WorldKeySaveData extends SavedData {
    public static final String FILE_ID = "ccs_ikm";
    public final byte[] key;

    public WorldKeySaveData() {
        var rand = new SecureRandom();
        var key = new byte[32];
        rand.nextBytes(key);
        this.key = key;
        this.setDirty();
    }

    public WorldKeySaveData(byte[] key) {
        this.key = key;
    }

    public static WorldKeySaveData load(CompoundTag serialized) {
        return new WorldKeySaveData(serialized.getByteArray("key"));
    }

    public byte[] derive(byte[] tag) {
        var digest = new Blake2sDigest(key);
        digest.update(tag, 0, tag.length);
        var result = new byte[32];
        digest.doFinal(result, 0);
        return result;
    }

    @Override
    @NotNull
    public CompoundTag save(CompoundTag tag) {
        tag.putByteArray("key", key);
        return tag;
    }
}
