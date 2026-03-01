/*
 * Copyright (C) 2026  PotatoLauncher contributors
 */
package moe.yushi.authlibinjector.transform.support;

public final class PotatoAuth121Profile {

	private final String version;
	private final String discardedPayloadClass;
	private final String discardedReadMethod;
	private final String discardedWriteMethod;
	private final String discardedIdAccessorMethod;
	private final String clientCommonPacketListenerClass;
	private final String clientCommonHandlePacketMethod;
	private final String clientPlayPacketListenerClass;
	private final String clientPlayHandlePayloadMethod;
	private final String clientboundCustomPayloadPacketClass;
	private final String clientboundPayloadAccessorMethod;
	private final String serverboundCustomPayloadPacketClass;
	private final String customPacketPayloadClass;
	private final String identifierClass;
	private final String friendlyByteBufClass;
	private final String minecraftClass;
	private final String userClass;
	private final String servicesClass;
	private final String minecraftGetUserMethod;
	private final String minecraftGetServicesMethod;
	private final String userGetProfileIdMethod;
	private final String userGetAccessTokenMethod;
	private final String servicesSessionServiceMethod;

	public PotatoAuth121Profile(
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
		this.version = version;
		this.discardedPayloadClass = discardedPayloadClass;
		this.discardedReadMethod = discardedReadMethod;
		this.discardedWriteMethod = discardedWriteMethod;
		this.discardedIdAccessorMethod = discardedIdAccessorMethod;
		this.clientCommonPacketListenerClass = clientCommonPacketListenerClass;
		this.clientCommonHandlePacketMethod = clientCommonHandlePacketMethod;
		this.clientPlayPacketListenerClass = clientPlayPacketListenerClass;
		this.clientPlayHandlePayloadMethod = clientPlayHandlePayloadMethod;
		this.clientboundCustomPayloadPacketClass = clientboundCustomPayloadPacketClass;
		this.clientboundPayloadAccessorMethod = clientboundPayloadAccessorMethod;
		this.serverboundCustomPayloadPacketClass = serverboundCustomPayloadPacketClass;
		this.customPacketPayloadClass = customPacketPayloadClass;
		this.identifierClass = identifierClass;
		this.friendlyByteBufClass = friendlyByteBufClass;
		this.minecraftClass = minecraftClass;
		this.userClass = userClass;
		this.servicesClass = servicesClass;
		this.minecraftGetUserMethod = minecraftGetUserMethod;
		this.minecraftGetServicesMethod = minecraftGetServicesMethod;
		this.userGetProfileIdMethod = userGetProfileIdMethod;
		this.userGetAccessTokenMethod = userGetAccessTokenMethod;
		this.servicesSessionServiceMethod = servicesSessionServiceMethod;
	}

	public String version() {
		return version;
	}

	public String discardedPayloadClass() {
		return discardedPayloadClass;
	}

	public String discardedReadMethod() {
		return discardedReadMethod;
	}

	public String discardedWriteMethod() {
		return discardedWriteMethod;
	}

	public String discardedIdAccessorMethod() {
		return discardedIdAccessorMethod;
	}

	public String clientCommonPacketListenerClass() {
		return clientCommonPacketListenerClass;
	}

	public String clientCommonHandlePacketMethod() {
		return clientCommonHandlePacketMethod;
	}

	public String clientPlayPacketListenerClass() {
		return clientPlayPacketListenerClass;
	}

	public String clientPlayHandlePayloadMethod() {
		return clientPlayHandlePayloadMethod;
	}

	public String clientboundCustomPayloadPacketClass() {
		return clientboundCustomPayloadPacketClass;
	}

	public String clientboundPayloadAccessorMethod() {
		return clientboundPayloadAccessorMethod;
	}

	public String serverboundCustomPayloadPacketClass() {
		return serverboundCustomPayloadPacketClass;
	}

	public String customPacketPayloadClass() {
		return customPacketPayloadClass;
	}

	public String identifierClass() {
		return identifierClass;
	}

	public String friendlyByteBufClass() {
		return friendlyByteBufClass;
	}

	public String minecraftClass() {
		return minecraftClass;
	}

	public String userClass() {
		return userClass;
	}

	public String servicesClass() {
		return servicesClass;
	}

	public String minecraftGetUserMethod() {
		return minecraftGetUserMethod;
	}

	public String minecraftGetServicesMethod() {
		return minecraftGetServicesMethod;
	}

	public String userGetProfileIdMethod() {
		return userGetProfileIdMethod;
	}

	public String userGetAccessTokenMethod() {
		return userGetAccessTokenMethod;
	}

	public String servicesSessionServiceMethod() {
		return servicesSessionServiceMethod;
	}

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
