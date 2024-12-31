package vg.skye;

import dan200.computercraft.api.ComputerCraftAPI;
import dan200.computercraft.api.peripheral.PeripheralLookup;
import net.fabricmc.api.ModInitializer;

import net.fabricmc.fabric.api.event.lifecycle.v1.ServerWorldEvents;
import net.fabricmc.fabric.api.object.builder.v1.block.entity.FabricBlockEntityTypeBuilder;
import net.minecraft.core.Registry;
import net.minecraft.core.registries.BuiltInRegistries;
import net.minecraft.core.registries.Registries;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.tags.TagKey;
import net.minecraft.world.item.BlockItem;
import net.minecraft.world.item.Item;
import net.minecraft.world.level.block.Block;
import net.minecraft.world.level.block.entity.BlockEntity;
import net.minecraft.world.level.block.entity.BlockEntityType;
import net.minecraft.world.level.block.state.BlockBehaviour;
import net.minecraft.world.level.material.MapColor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CCSecurity implements ModInitializer {
	public static final String MOD_ID = "cc-security";
	public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);
	public static WorldKeySaveData KEY_MATERIAL;

	public static final Block SAFE_BLOCK =
			register_block("safe", new SafeBlock(BlockBehaviour.Properties.of().mapColor(MapColor.METAL).strength(2F)));
	public static final BlockEntityType<SafeBlockEntity> SAFE_BLOCK_ENTITY =
			register_be("safe", SafeBlockEntity::new, SAFE_BLOCK);
	public static final TagKey<Item> SAFE_CAN_STORE =
			TagKey.create(Registries.ITEM, new ResourceLocation(MOD_ID, "safe_can_store"));

	private static Block register_block(String name, Block block) {
		var id = ResourceLocation.tryBuild(MOD_ID, name);
		BlockItem blockItem = new BlockItem(block, new Item.Properties());
		Registry.register(BuiltInRegistries.ITEM, id, blockItem);
		return Registry.register(BuiltInRegistries.BLOCK, id, block);
	}

	private static <T extends BlockEntity> BlockEntityType<T> register_be(String name,
																		  FabricBlockEntityTypeBuilder.Factory<? extends T> entityFactory,
																		  Block... blocks) {
		var id = ResourceLocation.tryBuild(MOD_ID, name);
		var blockEntityType = FabricBlockEntityTypeBuilder.create(entityFactory, blocks).build();
		return (BlockEntityType<T>) Registry.register(BuiltInRegistries.BLOCK_ENTITY_TYPE, id, blockEntityType);
	}

	@Override
	public void onInitialize() {
		ComputerCraftAPI.registerAPIFactory(CryptoApi::new);
		ComputerCraftAPI.registerAPIFactory(AuditApi::of);
		PeripheralLookup.get().registerForBlockEntity((f, s) -> new SafePeripheral(f), SAFE_BLOCK_ENTITY);
		ServerWorldEvents.LOAD.register((server, level) -> {
			if (server.overworld() != level)
				return;
			KEY_MATERIAL = level.getDataStorage().computeIfAbsent(WorldKeySaveData::load, WorldKeySaveData::new, WorldKeySaveData.FILE_ID);
			level.getDataStorage().save();
		});
	}
}