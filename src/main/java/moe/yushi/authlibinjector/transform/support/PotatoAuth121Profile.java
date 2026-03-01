/*
 * Copyright (C) 2026  PotatoLauncher contributors
 */
package moe.yushi.authlibinjector.transform.support;

public record PotatoAuth121Profile(
	String version,
	String discardedPayloadClass,
	String discardedReadMethod,
	String discardedWriteMethod,
	String discardedIdAccessorMethod,
	String clientCommonPacketListenerClass,
	String clientCommonHandlePacketMethod,
	String clientPlayPacketListenerClass,
	String clientPlayHandlePayloadMethod,
	String clientboundCustomPayloadPacketClass,
	String clientboundPayloadAccessorMethod,
	String serverboundCustomPayloadPacketClass,
	String customPacketPayloadClass,
	String identifierClass,
	String friendlyByteBufClass,
	String minecraftClass,
	String userClass,
	String servicesClass,
	String minecraftGetUserMethod,
	String minecraftGetServicesMethod,
	String userGetProfileIdMethod,
	String userGetAccessTokenMethod,
	String servicesSessionServiceMethod
) {

	public String discardedReadDescriptor() {
		return "(IL" + identifierClass + ";L" + friendlyByteBufClass + ";)L" + discardedPayloadClass + ";";
	}

	public String discardedWriteDescriptor() {
		return "(L" + discardedPayloadClass + ";L" + friendlyByteBufClass + ";)V";
	}

	public String clientCommonHandlePacketDescriptor() {
		return "(L" + clientboundCustomPayloadPacketClass + ";)V";
	}

	public String clientPlayHandlePayloadDescriptor() {
		return "(L" + customPacketPayloadClass + ";)V";
	}
}
