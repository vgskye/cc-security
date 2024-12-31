package vg.skye.mixin;

import dan200.computercraft.core.apis.ComputerAccess;
import dan200.computercraft.core.apis.IAPIEnvironment;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

@Mixin(value = ComputerAccess.class, remap = false)
public interface ComputerSystemAccessor {
    @Accessor
    IAPIEnvironment getEnvironment();
}
