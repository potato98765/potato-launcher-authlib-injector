/*
 * Copyright (C) 2026  PotatoLauncher contributors
 */
package moe.yushi.authlibinjector.transform.support;

import static java.nio.charset.StandardCharsets.UTF_8;
import static moe.yushi.authlibinjector.util.Logging.Level.DEBUG;
import static moe.yushi.authlibinjector.util.Logging.Level.INFO;
import static moe.yushi.authlibinjector.util.Logging.Level.WARNING;
import static moe.yushi.authlibinjector.util.Logging.log;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import moe.yushi.authlibinjector.transform.CallbackMethod;

public final class PotatoAuthClientBridge {

	private PotatoAuthClientBridge() {}

	private static final String CHANNEL = System.getProperty("potatoauth.channel", "potatoauth:auth");
	private static final long DUPLICATE_WINDOW_MS = Long.getLong("potatoauth.duplicateWindowMs", 250L);
	private static final Pattern NONCE_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{16,128}$");
	private static final Pattern JSON_NONCE_PATTERN = Pattern.compile("\"nonce\"\\s*:\\s*\"([A-Za-z0-9_-]{16,128})\"");
	private static final Pattern JSON_SERVER_ID_PATTERN = Pattern.compile("\"serverId\"\\s*:\\s*\"([A-Za-z0-9_-]{16,128})\"");
	private static final String MINECRAFT_REGISTER_CHANNEL = "minecraft:register";
	private static final Path DEBUG_LOG_PATH = Paths.get("potatoauth-bridge.log").toAbsolutePath();

	private static final Map<Object, byte[]> CAPTURED_BUFFER_BYTES = Collections.synchronizedMap(new IdentityHashMap<Object, byte[]>());
	private static final Map<Object, byte[]> PAYLOAD_BYTES = Collections.synchronizedMap(new IdentityHashMap<Object, byte[]>());
	private static final Map<Object, String> LAST_NONCE = Collections.synchronizedMap(new WeakHashMap<Object, String>());
	private static final Map<Object, Long> LAST_NONCE_AT = Collections.synchronizedMap(new WeakHashMap<Object, Long>());
	private static final Map<Object, Set<String>> SENT_CLIENT_REGISTRATIONS = Collections.synchronizedMap(new WeakHashMap<Object, Set<String>>());

	private static volatile PotatoAuth121Profile activeProfile;

	static {
		log(INFO, "[PotatoAuthBridge] Enabled for channel " + CHANNEL);
		appendDebugFile("Enabled for channel " + CHANNEL);
	}

	@CallbackMethod
	public static void captureIncomingDiscardedPayloadBytes(Object byteBufObj) {
		byte[] bytes = readReadableBytes(byteBufObj);
		if (bytes == null || bytes.length == 0) {
			return;
		}
		CAPTURED_BUFFER_BYTES.put(byteBufObj, bytes);
	}

	@CallbackMethod
	public static void completeIncomingDiscardedPayload(Object payloadObj, Object identifierObj, Object byteBufObj) {
		byte[] bytes = CAPTURED_BUFFER_BYTES.remove(byteBufObj);
		if (bytes == null || payloadObj == null || identifierObj == null) {
			return;
		}
		PAYLOAD_BYTES.put(payloadObj, bytes);
	}

	@CallbackMethod
	public static void writeOutgoingDiscardedPayloadBytes(Object payloadObj, Object byteBufObj) {
		if (payloadObj == null || byteBufObj == null) {
			return;
		}
		byte[] bytes = PAYLOAD_BYTES.remove(payloadObj);
		if (bytes == null || bytes.length == 0) {
			return;
		}
		writeBytes(byteBufObj, bytes);
	}

	@CallbackMethod
	public static void onClientboundCustomPayloadPacket(Object listenerObj, Object packetObj) {
		if (listenerObj == null || packetObj == null) {
			return;
		}
		try {
			PotatoAuth121Profile profile = resolveProfile(listenerObj, null);
			if (profile == null) {
				debug("No PotatoAuth profile matched for listener class " + listenerObj.getClass().getName());
				return;
			}

			Object payload = invokeNoArg(packetObj, profile.clientboundPayloadAccessorMethod());
			onClientboundCustomPayload(listenerObj, payload);
		} catch (Throwable t) {
			log(WARNING, "Failed to process PotatoAuth challenge packet", t);
		}
	}

	@CallbackMethod
	public static void onClientboundCustomPayload(Object listenerObj, Object payloadObj) {
		if (listenerObj == null || payloadObj == null) {
			return;
		}
		try {
			PotatoAuth121Profile profile = resolveProfile(listenerObj, payloadObj);
			if (profile == null) {
				return;
			}
			if (!profile.discardedPayloadClass().equals(payloadObj.getClass().getName())) {
				return;
			}

			Object identifier = invokeNoArg(payloadObj, profile.discardedIdAccessorMethod());
			if (identifier == null) {
				return;
			}
			String channel = String.valueOf(identifier);

			byte[] challengeBytes = PAYLOAD_BYTES.remove(payloadObj);
			if (challengeBytes == null) {
				return;
			}
			if (MINECRAFT_REGISTER_CHANNEL.equals(channel)) {
				handleServerRegisterPayload(listenerObj, challengeBytes, profile);
				return;
			}
			if (!isLikelyPotatoChallenge(channel, challengeBytes)) {
				return;
			}

			String nonce = extractNonce(challengeBytes);
			if (nonce == null) {
				log(WARNING, "PotatoAuth challenge received, but nonce could not be parsed");
				return;
			}
			if (isDuplicate(listenerObj, nonce)) {
				log(DEBUG, "Ignoring duplicate PotatoAuth challenge nonce=" + nonce);
				return;
			}

			joinServerWithNonce(listenerObj, nonce, profile);
			sendNonceResponse(listenerObj, nonce, channel, profile);
			log(INFO, "PotatoAuth challenge handled automatically nonce=" + nonce + " profile=" + profile.version());
		} catch (Throwable t) {
			log(WARNING, "Failed to process PotatoAuth challenge payload", t);
		}
	}

	private static PotatoAuth121Profile resolveProfile(Object listenerObj, Object payloadObj) {
		PotatoAuth121Profile cached = activeProfile;
		if (cached != null && profileMatches(cached, listenerObj, payloadObj)) {
			return cached;
		}

		String listenerClass = listenerObj != null ? listenerObj.getClass().getName() : null;
		String payloadClass = payloadObj != null ? payloadObj.getClass().getName() : null;

		PotatoAuth121Profile resolved = null;
		if (listenerObj != null) {
			resolved = findProfileByClassHierarchy(listenerObj.getClass());
		}
		if (resolved == null && payloadClass != null) {
			resolved = PotatoAuth121Profiles.findByAnyClassName(payloadClass);
		}
		if (resolved != null) {
			activeProfile = resolved;
		}
		return resolved;
	}

	private static boolean profileMatches(PotatoAuth121Profile profile, Object listenerObj, Object payloadObj) {
		if (listenerObj != null) {
			if (!matchesClassOrSuperclass(listenerObj.getClass(), profile.clientCommonPacketListenerClass())
				&& !matchesClassOrSuperclass(listenerObj.getClass(), profile.clientPlayPacketListenerClass())) {
				return false;
			}
		}
		if (payloadObj != null) {
			return profile.discardedPayloadClass().equals(payloadObj.getClass().getName());
		}
		return true;
	}

	private static boolean isLikelyPotatoChallenge(String channel, byte[] bytes) {
		if (channel != null && channel.toLowerCase().contains("potatoauth")) {
			return true;
		}
		if (bytes == null || bytes.length == 0) {
			return false;
		}
		String text = new String(bytes, UTF_8);
		if (text.contains("POTATOAUTH_CHALLENGE")) {
			return true;
		}
		return text.contains("\"packetType\"") && text.contains("CHALLENGE");
	}

	private static void handleServerRegisterPayload(Object listenerObj, byte[] bytes, PotatoAuth121Profile profile) {
		String text = new String(bytes, UTF_8);
		if (text.isEmpty()) {
			return;
		}

		String[] channels = text.split("\\u0000");
		for (String channel : channels) {
			String trimmed = channel == null ? "" : channel.trim();
			if (trimmed.isEmpty()) {
				continue;
			}
			if (CHANNEL.equals(trimmed) || trimmed.toLowerCase().contains("potatoauth")) {
				ensureClientRegisterSent(listenerObj, trimmed, profile);
			}
		}
	}

	private static void ensureClientRegisterSent(Object listenerObj, String channelToRegister, PotatoAuth121Profile profile) {
		synchronized (SENT_CLIENT_REGISTRATIONS) {
			Set<String> sent = SENT_CLIENT_REGISTRATIONS.get(listenerObj);
			if (sent == null) {
				sent = new HashSet<String>();
				SENT_CLIENT_REGISTRATIONS.put(listenerObj, sent);
			}
			if (sent.contains(channelToRegister)) {
				return;
			}
			try {
				sendRawPluginPayload(listenerObj, MINECRAFT_REGISTER_CHANNEL, channelToRegister.getBytes(UTF_8), profile);
				debug("Sent client register for channel=" + channelToRegister);
				sent.add(channelToRegister);
			} catch (Throwable t) {
				debug("Failed to send client register for " + channelToRegister + ": " + t);
			}
		}
	}

	private static boolean isDuplicate(Object listenerObj, String nonce) {
		long now = System.currentTimeMillis();
		String previousNonce = LAST_NONCE.get(listenerObj);
		Long previousAt = LAST_NONCE_AT.get(listenerObj);
		if (nonce.equals(previousNonce) && previousAt != null && now - previousAt.longValue() < DUPLICATE_WINDOW_MS) {
			return true;
		}
		LAST_NONCE.put(listenerObj, nonce);
		LAST_NONCE_AT.put(listenerObj, Long.valueOf(now));
		return false;
	}

	private static String extractNonce(byte[] bytes) {
		if (bytes == null || bytes.length == 0) {
			return null;
		}

		String nonce = parseBinaryChallengeNonce(bytes);
		if (nonce != null) {
			return nonce;
		}

		String text = new String(bytes, UTF_8).trim();
		if (text.isEmpty()) {
			return null;
		}

		Matcher jsonNonce = JSON_NONCE_PATTERN.matcher(text);
		if (jsonNonce.find()) {
			return sanitizeNonce(jsonNonce.group(1));
		}

		Matcher jsonServerId = JSON_SERVER_ID_PATTERN.matcher(text);
		if (jsonServerId.find()) {
			return sanitizeNonce(jsonServerId.group(1));
		}

		int separator = text.indexOf('|');
		if (separator >= 0) {
			text = text.substring(0, separator);
		}
		return sanitizeNonce(text);
	}

	private static String parseBinaryChallengeNonce(byte[] bytes) {
		try {
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
			String packetType = in.readUTF();
			if (!"POTATOAUTH_CHALLENGE".equals(packetType)) {
				return null;
			}
			return sanitizeNonce(in.readUTF());
		} catch (Throwable ignored) {
			return null;
		}
	}

	private static String sanitizeNonce(String raw) {
		if (raw == null) {
			return null;
		}
		String nonce = raw.trim();
		if (!NONCE_PATTERN.matcher(nonce).matches()) {
			return null;
		}
		return nonce;
	}

	private static void joinServerWithNonce(Object listenerObj, String nonce, PotatoAuth121Profile profile) throws Exception {
		Object minecraft = getFieldValueByTypeName(listenerObj, profile.minecraftClass());
		if (minecraft == null) {
			throw new IllegalStateException("Failed to locate Minecraft instance in listener");
		}

		Object user = invokeNoArgIfExists(minecraft, profile.minecraftGetUserMethod());
		if (user == null) {
			user = getFieldValueByTypeName(minecraft, profile.userClass());
		}
		if (user == null) {
			throw new IllegalStateException("Failed to locate User object in Minecraft");
		}

		Object profileIdObj = invokeNoArgIfExists(user, profile.userGetProfileIdMethod());
		if (!(profileIdObj instanceof UUID)) {
			profileIdObj = getFieldValueByType(user, UUID.class);
		}
		if (!(profileIdObj instanceof UUID)) {
			throw new IllegalStateException("Failed to obtain profile UUID from User");
		}
		UUID profileId = (UUID) profileIdObj;

		Object accessTokenObj = invokeNoArgIfExists(user, profile.userGetAccessTokenMethod());
		if (!(accessTokenObj instanceof String) || ((String) accessTokenObj).isEmpty()) {
			accessTokenObj = getFieldValueByType(user, String.class);
		}
		if (!(accessTokenObj instanceof String) || ((String) accessTokenObj).isEmpty()) {
			throw new IllegalStateException("Failed to obtain access token from User");
		}
		String accessToken = (String) accessTokenObj;

		Object services = invokeNoArgIfExists(minecraft, profile.minecraftGetServicesMethod());
		if (services == null) {
			services = getFieldValueByTypeName(minecraft, profile.servicesClass());
		}
		Object sessionService = resolveMinecraftSessionService(minecraft, services, profile);
		if (sessionService == null) {
			throw new IllegalStateException("Failed to locate MinecraftSessionService");
		}

		Method joinServer = findMethod(sessionService.getClass(), "joinServer", 3);
		if (joinServer == null) {
			throw new NoSuchMethodException("MinecraftSessionService.joinServer(UUID,String,String) not found");
		}
		joinServer.invoke(sessionService, profileId, accessToken, nonce);
	}

	private static void sendNonceResponse(Object listenerObj, String nonce, String channel, PotatoAuth121Profile profile) throws Exception {
		sendRawPluginPayload(listenerObj, channel, nonce.getBytes(UTF_8), profile);
	}

	private static void sendRawPluginPayload(Object listenerObj, String channel, byte[] payloadBytes, PotatoAuth121Profile profile) throws Exception {
		ClassLoader classLoader = listenerObj.getClass().getClassLoader();
		Class<?> identifierClass = Class.forName(profile.identifierClass(), false, classLoader);
		Class<?> discardedPayloadClass = Class.forName(profile.discardedPayloadClass(), false, classLoader);
		Class<?> customPayloadInterface = Class.forName(profile.customPacketPayloadClass(), false, classLoader);
		Class<?> serverboundCustomPayloadPacketClass = Class.forName(profile.serverboundCustomPayloadPacketClass(), false, classLoader);

		Constructor<?> idCtor = identifierClass.getDeclaredConstructor(String.class, String.class);
		idCtor.setAccessible(true);
		String namespace = "minecraft";
		String path = "register";
		if (channel != null) {
			int separator = channel.indexOf(':');
			if (separator > 0 && separator < channel.length() - 1) {
				namespace = channel.substring(0, separator);
				path = channel.substring(separator + 1);
			} else {
				path = channel;
			}
		}
		Object idObj = idCtor.newInstance(namespace, path);

		Constructor<?> payloadCtor = discardedPayloadClass.getDeclaredConstructor(identifierClass);
		payloadCtor.setAccessible(true);
		Object payloadObj = payloadCtor.newInstance(idObj);
		PAYLOAD_BYTES.put(payloadObj, payloadBytes);

		Constructor<?> packetCtor = serverboundCustomPayloadPacketClass.getDeclaredConstructor(customPayloadInterface);
		packetCtor.setAccessible(true);
		Object packetObj = packetCtor.newInstance(payloadObj);

		Method sendMethod = findSendMethod(listenerObj.getClass(), packetObj.getClass());
		if (sendMethod == null) {
			throw new NoSuchMethodException("Listener send(Packet) method not found");
		}
		sendMethod.invoke(listenerObj, packetObj);
	}

	private static PotatoAuth121Profile findProfileByClassHierarchy(Class<?> type) {
		Class<?> current = type;
		while (current != null) {
			PotatoAuth121Profile profile = PotatoAuth121Profiles.findByAnyClassName(current.getName());
			if (profile != null) {
				return profile;
			}
			current = current.getSuperclass();
		}
		return null;
	}

	private static boolean matchesClassOrSuperclass(Class<?> type, String expectedClassName) {
		if (type == null || expectedClassName == null || expectedClassName.isEmpty()) {
			return false;
		}
		Class<?> current = type;
		while (current != null) {
			if (expectedClassName.equals(current.getName())) {
				return true;
			}
			current = current.getSuperclass();
		}
		return false;
	}

	private static Object resolveMinecraftSessionService(Object minecraft, Object services, PotatoAuth121Profile profile) throws Exception {
		if (services != null) {
			Object sessionService = invokeNoArgIfExists(services, profile.servicesSessionServiceMethod());
			if (sessionService == null) {
				Method fallback = findNoArgMethodByReturnTypeName(services.getClass(), "com.mojang.authlib.minecraft.MinecraftSessionService");
				if (fallback != null) {
					sessionService = fallback.invoke(services);
				}
			}
			if (sessionService != null) {
				return sessionService;
			}
		}

		Object direct = invokeNoArgIfExists(minecraft, "getMinecraftSessionService");
		if (direct != null) {
			return direct;
		}

		Method byReturnType = findNoArgMethodByReturnTypeName(minecraft.getClass(), "com.mojang.authlib.minecraft.MinecraftSessionService");
		if (byReturnType != null) {
			Object value = byReturnType.invoke(minecraft);
			if (value != null) {
				return value;
			}
		}

		return getFieldValueByTypeName(minecraft, "com.mojang.authlib.minecraft.MinecraftSessionService");
	}

	private static Method findSendMethod(Class<?> listenerClass, Class<?> packetClass) {
		for (Method method : listenerClass.getMethods()) {
			if (method.getParameterCount() != 1 || method.getReturnType() != Void.TYPE) {
				continue;
			}
			Class<?> parameter = method.getParameterTypes()[0];
			if (parameter.isAssignableFrom(packetClass)) {
				method.setAccessible(true);
				return method;
			}
		}
		for (Method method : listenerClass.getDeclaredMethods()) {
			if (method.getParameterCount() != 1 || method.getReturnType() != Void.TYPE) {
				continue;
			}
			Class<?> parameter = method.getParameterTypes()[0];
			if (parameter.isAssignableFrom(packetClass)) {
				method.setAccessible(true);
				return method;
			}
		}
		return null;
	}

	private static Field findField(Class<?> type, String name) {
		Class<?> current = type;
		while (current != null) {
			try {
				Field field = current.getDeclaredField(name);
				field.setAccessible(true);
				return field;
			} catch (NoSuchFieldException ignored) {
				current = current.getSuperclass();
			}
		}
		return null;
	}

	private static Object getFieldValueByTypeName(Object target, String className) {
		if (target == null || className == null || className.isEmpty()) {
			return null;
		}
		Class<?> current = target.getClass();
		while (current != null) {
			for (Field field : current.getDeclaredFields()) {
				if (className.equals(field.getType().getName())) {
					try {
						field.setAccessible(true);
						Object value = field.get(target);
						if (value != null) {
							return value;
						}
					} catch (IllegalAccessException ignored) {
					}
				}
			}
			current = current.getSuperclass();
		}
		return null;
	}

	private static Object getFieldValueByType(Object target, Class<?> type) {
		if (target == null || type == null) {
			return null;
		}
		Class<?> current = target.getClass();
		while (current != null) {
			for (Field field : current.getDeclaredFields()) {
				if (type.isAssignableFrom(field.getType())) {
					try {
						field.setAccessible(true);
						Object value = field.get(target);
						if (value != null) {
							return value;
						}
					} catch (IllegalAccessException ignored) {
					}
				}
			}
			current = current.getSuperclass();
		}
		return null;
	}

	private static Method findMethod(Class<?> type, String name, int paramCount) {
		if (name == null || name.isEmpty()) {
			return null;
		}
		for (Method method : type.getMethods()) {
			if (name.equals(method.getName()) && method.getParameterCount() == paramCount) {
				method.setAccessible(true);
				return method;
			}
		}
		Class<?> current = type;
		while (current != null) {
			for (Method method : current.getDeclaredMethods()) {
				if (name.equals(method.getName()) && method.getParameterCount() == paramCount) {
					method.setAccessible(true);
					return method;
				}
			}
			current = current.getSuperclass();
		}
		return null;
	}

	private static Method findNoArgMethodByReturnTypeName(Class<?> type, String returnTypeName) {
		for (Method method : type.getMethods()) {
			if (method.getParameterCount() == 0 && method.getReturnType().getName().equals(returnTypeName)) {
				method.setAccessible(true);
				return method;
			}
		}
		Class<?> current = type;
		while (current != null) {
			for (Method method : current.getDeclaredMethods()) {
				if (method.getParameterCount() == 0 && method.getReturnType().getName().equals(returnTypeName)) {
					method.setAccessible(true);
					return method;
				}
			}
			current = current.getSuperclass();
		}
		return null;
	}

	private static byte[] readReadableBytes(Object friendlyByteBufObj) {
		try {
			Method readableBytesMethod = findMethod(friendlyByteBufObj.getClass(), "readableBytes", 0);
			Method readerIndexMethod = findMethod(friendlyByteBufObj.getClass(), "readerIndex", 0);
			Method getBytesMethod = findMethodWithParameterTypes(friendlyByteBufObj.getClass(), "getBytes", int.class, byte[].class);
			if (readableBytesMethod == null || readerIndexMethod == null || getBytesMethod == null) {
				return null;
			}

			Object readableObj = readableBytesMethod.invoke(friendlyByteBufObj);
			Object readerIndexObj = readerIndexMethod.invoke(friendlyByteBufObj);
			if (!(readableObj instanceof Integer) || !(readerIndexObj instanceof Integer)) {
				return null;
			}

			int readable = ((Integer) readableObj).intValue();
			int readerIndex = ((Integer) readerIndexObj).intValue();
			if (readable <= 0 || readable > 1048576) {
				return null;
			}

			byte[] bytes = new byte[readable];
			getBytesMethod.invoke(friendlyByteBufObj, Integer.valueOf(readerIndex), bytes);
			return bytes;
		} catch (Throwable ignored) {
			return null;
		}
	}

	private static void writeBytes(Object friendlyByteBufObj, byte[] bytes) {
		try {
			Method writeBytesMethod = findMethodWithParameterTypes(friendlyByteBufObj.getClass(), "writeBytes", byte[].class);
			if (writeBytesMethod == null) {
				return;
			}
			writeBytesMethod.invoke(friendlyByteBufObj, bytes);
		} catch (Throwable ignored) {
		}
	}

	private static Method findMethodWithParameterTypes(Class<?> type, String name, Class<?>... parameterTypes) {
		for (Method method : type.getMethods()) {
			if (!name.equals(method.getName())) {
				continue;
			}
			Class<?>[] params = method.getParameterTypes();
			if (params.length != parameterTypes.length) {
				continue;
			}
			boolean matches = true;
			for (int i = 0; i < params.length; i++) {
				if (!params[i].equals(parameterTypes[i])) {
					matches = false;
					break;
				}
			}
			if (matches) {
				method.setAccessible(true);
				return method;
			}
		}
		return null;
	}

	private static Object invokeNoArg(Object target, String methodName) throws Exception {
		Method method = findMethod(target.getClass(), methodName, 0);
		if (method == null) {
			throw new NoSuchMethodException(methodName + "() not found on " + target.getClass().getName());
		}
		try {
			return method.invoke(target);
		} catch (InvocationTargetException e) {
			Throwable cause = e.getCause() == null ? e : e.getCause();
			if (cause instanceof Exception) {
				throw (Exception) cause;
			}
			if (cause instanceof Error) {
				throw (Error) cause;
			}
			throw new RuntimeException(cause);
		}
	}

	private static Object invokeNoArgIfExists(Object target, String methodName) {
		if (target == null || methodName == null || methodName.isEmpty()) {
			return null;
		}
		try {
			Method method = findMethod(target.getClass(), methodName, 0);
			if (method == null) {
				return null;
			}
			return method.invoke(target);
		} catch (Throwable ignored) {
			return null;
		}
	}

	private static void debug(String message) {
		log(DEBUG, "[PotatoAuthBridge] " + message);
		appendDebugFile(message);
	}

	private static void appendDebugFile(String message) {
		try {
			String line = "[PotatoAuthBridge] " + message + System.lineSeparator();
			Files.write(DEBUG_LOG_PATH, line.getBytes(UTF_8), StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
		} catch (IOException ignored) {
		}
	}
}
