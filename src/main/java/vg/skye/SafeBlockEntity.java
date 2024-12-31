package vg.skye;

import net.minecraft.core.BlockPos;
import net.minecraft.core.NonNullList;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.ListTag;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.level.block.entity.BlockEntity;
import net.minecraft.world.level.block.entity.BlockEntityType;
import net.minecraft.world.level.block.state.BlockState;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class SafeBlockEntity extends BlockEntity {
    private final SafePeripheral peripheral = new SafePeripheral(this);
    public final NonNullList<ItemStack> inventory = NonNullList.create();
    public byte[] passwordHash;
    public byte[] passwordSalt;

    public SafeBlockEntity(BlockPos blockPos, BlockState blockState) {
        super(CCSecurity.SAFE_BLOCK_ENTITY, blockPos, blockState);
        var salt = new byte[16];
        var rand = new SecureRandom();
        rand.nextBytes(salt);
        passwordSalt = salt;
        var argon2 = new Argon2BytesGenerator();
        var config = new Argon2Parameters
                .Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(19456)
                .withIterations(2)
                .withParallelism(1)
                .build();
        argon2.init(config);
        var hash = new byte[32];
        argon2.generateBytes("hunter2".getBytes(StandardCharsets.UTF_8), hash);
        passwordHash = hash;
    }

    @Override
    public void load(CompoundTag nbt) {
        super.load(nbt);
        passwordHash = nbt.getByteArray("PasswordHash");
        passwordSalt = nbt.getByteArray("PasswordSalt");
        ListTag items = nbt.getList("Items", 10);
        for (int i = 0; i < items.size(); i++) {
            CompoundTag item = items.getCompound(i);
            inventory.add(ItemStack.of(item));
        }
    }

    @Override
    protected void saveAdditional(CompoundTag nbt) {
        nbt.putByteArray("PasswordHash", passwordHash);
        nbt.putByteArray("PasswordSalt", passwordSalt);
        var items = new ListTag();
        for (ItemStack itemStack : inventory) {
            if (itemStack.isEmpty())
                continue;
            var item = new CompoundTag();
            itemStack.save(item);
            items.add(item);
        }
        nbt.put("Items", items);
        super.saveAdditional(nbt);
    }
}
