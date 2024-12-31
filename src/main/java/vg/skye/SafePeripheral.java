package vg.skye;

import dan200.computercraft.api.detail.VanillaDetailRegistries;
import dan200.computercraft.api.lua.LuaException;
import dan200.computercraft.api.lua.LuaFunction;
import dan200.computercraft.api.peripheral.IComputerAccess;
import dan200.computercraft.api.peripheral.IPeripheral;
import net.fabricmc.fabric.api.transfer.v1.item.ItemStorage;
import net.fabricmc.fabric.api.transfer.v1.item.ItemVariant;
import net.fabricmc.fabric.api.transfer.v1.storage.SlottedStorage;
import net.fabricmc.fabric.api.transfer.v1.transaction.Transaction;
import net.minecraft.core.BlockPos;
import net.minecraft.core.Direction;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.level.Level;
import net.minecraft.world.level.block.entity.BlockEntity;
import net.minecraft.world.level.block.state.BlockState;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

import static dan200.computercraft.core.util.ArgumentHelpers.assertBetween;

public class SafePeripheral implements IPeripheral {
    private final SafeBlockEntity safe;

    public SafePeripheral(SafeBlockEntity safe) {
        this.safe = safe;
    }

    @Override
    public String getType() {
        return "safe";
    }

    @Override
    public boolean equals(IPeripheral other) {
        return this == other || (other instanceof SafePeripheral otherPrinter && otherPrinter.safe == safe);
    }

    @Override
    public Object getTarget() {
        return safe;
    }

    private boolean isPasswordGood(String password) {
        var argon2 = new Argon2BytesGenerator();
        var config = new Argon2Parameters
                .Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(safe.passwordSalt)
                .withMemoryAsKB(19456)
                .withIterations(2)
                .withParallelism(1)
                .build();
        argon2.init(config);
        var hash = new byte[32];
        argon2.generateBytes(CryptoApi.toBytes(password), hash);
        return MessageDigest.isEqual(hash, safe.passwordHash);
    }

    @LuaFunction(mainThread = true)
    public final void changePassword(String currentPassword, String newPassword) throws LuaException {
        if (!isPasswordGood(currentPassword)) {
            throw new LuaException("Wrong password");
        }
        var salt = new byte[16];
        var rand = new SecureRandom();
        rand.nextBytes(salt);
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
        argon2.generateBytes(CryptoApi.toBytes(newPassword), hash);
        safe.passwordSalt = salt;
        safe.passwordHash = hash;
        safe.setChanged();
    }

    @LuaFunction(mainThread = true)
    public final Map<String, Object>[] list(String password) throws LuaException {
        if (!isPasswordGood(password)) {
            throw new LuaException("Wrong password");
        }
        var result = new ArrayList<Map<String, Object>>();
        for (ItemStack itemStack : safe.inventory) {
            if (itemStack.isEmpty())
                continue;
            result.add(VanillaDetailRegistries.ITEM_STACK.getBasicDetails(itemStack));
        }
        return result.toArray(new Map[0]);
    }

    @LuaFunction(mainThread = true)
    public final Map<String, ?> getItemDetail(String password, int slot) throws LuaException {
        if (!isPasswordGood(password)) {
            throw new LuaException("Wrong password");
        }
        int acc = 0;
        for (ItemStack itemStack : safe.inventory) {
            if (itemStack.isEmpty())
                continue;
            acc++;
            if (acc == slot)
                return VanillaDetailRegistries.ITEM_STACK.getDetails(itemStack);
        }
        throw new LuaException("Slot out of range");
    }

    @LuaFunction(mainThread = true)
    public final int pushItems(
            IComputerAccess computer, String password,
            String toName, int fromSlot, Optional<Integer> limit, Optional<Integer> toSlot
    ) throws LuaException {
        if (!isPasswordGood(password)) {
            throw new LuaException("Wrong password");
        }
        // Find location to transfer to
        var location = computer.getAvailablePeripheral(toName);
        if (location == null)
            throw new LuaException("Target '" + toName + "' does not exist");

        var to = extractHandler(location);
        if (to == null)
            throw new LuaException("Target '" + toName + "' is not an inventory");

        // Validate slots
        int actualLimit = limit.orElse(Integer.MAX_VALUE);
        if (toSlot.isPresent())
            assertBetween(toSlot.get(), 1, to.getSlots().size(), "To slot out of range (%s)");

        if (actualLimit <= 0) return 0;
        int acc = 0;
        for (ItemStack itemStack : safe.inventory) {
            CCSecurity.LOGGER.info("slot {} {}", acc, itemStack);
            if (itemStack.isEmpty())
                continue;
            acc++;
            if (acc == fromSlot) {
                try (var transaction = Transaction.openOuter()) {
                    var transferSlot = to;
                    if (toSlot.isPresent()) {
                        transferSlot = to.getSlot(toSlot.get());
                    }
                    var toTransfer = Math.min(itemStack.getCount(), actualLimit);
                    var transferred = transferSlot.insert(ItemVariant.of(itemStack), toTransfer, transaction);
                    itemStack.setCount((int) (itemStack.getCount() - transferred));
                    safe.setChanged();
                    transaction.commit();
                    return (int) transferred;
                }
            }
        }
        throw new LuaException("From slot out of range");
    }

    @LuaFunction(mainThread = true)
    public final int pullItems(
            IComputerAccess computer, String password,
            String fromName, int fromSlot, Optional<Integer> limit
    ) throws LuaException {
        if (!isPasswordGood(password)) {
            throw new LuaException("Wrong password");
        }
        // Find location to transfer to
        var location = computer.getAvailablePeripheral(fromName);
        if (location == null)
            throw new LuaException("Target '" + fromName + "' does not exist");

        var from = extractHandler(location);
        if (from == null)
            throw new LuaException("Source '" + fromName + "' is not an inventory");

        // Validate slots
        int actualLimit = limit.orElse(Integer.MAX_VALUE);
        assertBetween(fromSlot, 1, from.getSlots().size(), "From slot out of range (%s)");

        if (actualLimit <= 0) return 0;
        try (var transaction = Transaction.openOuter()) {
            var transferSlot = from.getSlot(fromSlot - 1);
            if (!transferSlot.supportsExtraction())
                return 0;
            if (transferSlot.isResourceBlank())
                return 0;
            var resource = transferSlot.getResource();
            if (!resource.getItem().builtInRegistryHolder().is(CCSecurity.SAFE_CAN_STORE))
                return 0;
            var inserted = transferSlot.extract(resource, actualLimit, transaction);
            var acc = inserted;
            for (ItemStack itemStack : safe.inventory) {
                if (itemStack.isEmpty())
                    continue;
                if (acc <= 0)
                    return (int) inserted;
                if (resource.matches(itemStack) && itemStack.getCount() < itemStack.getMaxStackSize()) {
                     var canStack = Math.min(itemStack.getMaxStackSize() - itemStack.getCount(), acc);
                     itemStack.setCount((int) (itemStack.getCount() + canStack));
                     acc -= canStack;
                }
            }
            while (acc > 0) {
                var canStack = Math.min(resource.getItem().getMaxStackSize(), acc);
                safe.inventory.add(resource.toStack((int) canStack));
                acc -= canStack;
            }
            safe.setChanged();
            transaction.commit();
            return (int) inserted;
        }
    }

    @Nullable
    private static SlottedStorage<ItemVariant> extractHandler(IPeripheral peripheral) {
        var object = peripheral.getTarget();
        var direction = peripheral instanceof dan200.computercraft.shared.peripheral.generic.GenericPeripheral sided ? sided.side() : null;

        if (object instanceof BlockEntity blockEntity) {
            if (blockEntity.isRemoved()) return null;

            var found = extractContainerImpl(blockEntity.getLevel(), blockEntity.getBlockPos(), blockEntity.getBlockState(), blockEntity, direction);
            if (found != null) return found;
        }

        return null;
    }

    private static @Nullable SlottedStorage<ItemVariant> extractContainerImpl(Level level, BlockPos pos, BlockState state, @Nullable BlockEntity blockEntity, @Nullable Direction direction) {
        var internal = ItemStorage.SIDED.find(level, pos, state, blockEntity, null);
        if (internal instanceof SlottedStorage<ItemVariant> storage) return storage;

        if (direction != null) {
            var external = ItemStorage.SIDED.find(level, pos, state, blockEntity, direction);
            if (external instanceof SlottedStorage<ItemVariant> storage) return storage;
        }

        return null;
    }
}
