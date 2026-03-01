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
		debug("Captured discarded payload bytes length=" + bytes.length);
	}

	@CallbackMethod
	public static void completeIncomingDiscardedPayload(Object payloadObj, Object identifierObj, Object byteBufObj) {
		byte[] bytes = CAPTURED_BUFFER_BYTES.remove(byteBufObj);
		if (bytes == null || payloadObj == null || identifierObj == null) {
			return;
		}
		PAYLOAD_BYTES.put(payloadObj, bytes);
		debug("Stored payload bytes for channel " + String.valueOf(identifierObj) + " length=" + bytes.length);
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
		debug("Wrote outgoing payload bytes length=" + bytes.length);
	}

	@CallbackMethod
	public static void onClientboundCustomPayloadPacket(Object listenerObj, Object packetObj) {
		if (listenerObj == null || packetObj == null) {
			return;
		}
		try {
			debug("Clientbound packet hook called listener=" + listenerObj.getClass().getName() + " packet=" + packetObj.getClass().getName());
			Object payload = invokeNoArg(packetObj, "b");
			onClientboundCustomPayload(listenerObj, payload);
		} catch (Throwable t) {
			log(WARNING, "Failed to process PotatoAuth challenge packet", t);
			debug("Packet hook error: " + t);
		}
	}

	@CallbackMethod
	public static void onClientboundCustomPayload(Object listenerObj, Object payloadObj) {
		if (listenerObj == null || payloadObj == null) {
			return;
		}
		try {
			debug("Custom payload hook called listener=" + listenerObj.getClass().getName() + " payload=" + payloadObj.getClass().getName());
			if (!"ace".equals(payloadObj.getClass().getName())) {
				return;
			}

			Object identifier = invokeNoArg(payloadObj, "b");
			if (identifier == null) {
				debug("Discarded payload without identifier");
				return;
			}
			String channel = String.valueOf(identifier);

			byte[] challengeBytes = PAYLOAD_BYTES.remove(payloadObj);
			if (challengeBytes == null) {
				debug("No payload bytes captured for " + channel + " (expected challenge channel " + CHANNEL + ")");
				return;
			}
			debug("Payload bytes received for " + channel + " length=" + challengeBytes.length);
			if (MINECRAFT_REGISTER_CHANNEL.equals(channel)) {
				handleServerRegisterPayload(listenerObj, challengeBytes);
				return;
			}
			if (!isLikelyPotatoChallenge(channel, challengeBytes)) {
				debug("Discarded payload ignored (not potato challenge) channel=" + channel);
				return;
			}

			String nonce = extractNonce(challengeBytes);
			if (nonce == null) {
				log(WARNING, "PotatoAuth challenge received, but nonce could not be parsed");
				debug("Nonce parse failed for channel=" + channel + " bytes=" + challengeBytes.length);
				return;
			}
			debug("Parsed nonce=" + nonce + " channel=" + channel);
			if (isDuplicate(listenerObj, nonce)) {
				log(DEBUG, "Ignoring duplicate PotatoAuth challenge nonce=" + nonce);
				debug("Duplicate nonce ignored=" + nonce);
				return;
			}

			joinServerWithNonce(listenerObj, nonce);
			debug("joinServer success nonce=" + nonce);
			sendNonceResponse(listenerObj, nonce, channel);
			debug("Response packet sent nonce=" + nonce + " channel=" + channel);
			log(INFO, "PotatoAuth challenge handled automatically nonce=" + nonce);
		} catch (Throwable t) {
			log(WARNING, "Failed to process PotatoAuth challenge payload", t);
			debug("Payload hook error: " + t);
		}
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

	private static void handleServerRegisterPayload(Object listenerObj, byte[] bytes) {
		String text = new String(bytes, UTF_8);
		if (text.isEmpty()) {
			debug("Server register payload empty");
			return;
		}

		String[] channels = text.split("\\u0000");
		debug("Server register channels=" + text.replace('\u0000', ','));
		for (String channel : channels) {
			String trimmed = channel == null ? "" : channel.trim();
			if (trimmed.isEmpty()) {
				continue;
			}
			if (CHANNEL.equals(trimmed) || trimmed.toLowerCase().contains("potatoauth")) {
				ensureClientRegisterSent(listenerObj, trimmed);
			}
		}
	}

	private static void ensureClientRegisterSent(Object listenerObj, String channelToRegister) {
		synchronized (SENT_CLIENT_REGISTRATIONS) {
			Set<String> sent = SENT_CLIENT_REGISTRATIONS.get(listenerObj);
			if (sent == null) {
				sent = new HashSet<String>();
				SENT_CLIENT_REGISTRATIONS.put(listenerObj, sent);
			}
			if (sent.contains(channelToRegister)) {
				debug("Client register already sent for " + channelToRegister);
				return;
			}
			try {
				sendRawPluginPayload(listenerObj, MINECRAFT_REGISTER_CHANNEL, channelToRegister.getBytes(UTF_8));
				sent.add(channelToRegister);
				debug("Sent client register for " + channelToRegister);
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
			String nonce = sanitizeNonce(in.readUTF());
			if (nonce == null) {
				return null;
			}
			return nonce;
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

	private static void joinServerWithNonce(Object listenerObj, String nonce) throws Exception {
		Object minecraft = getFieldValue(listenerObj, "a");
		if (minecraft == null) {
			throw new IllegalStateException("Failed to get Minecraft instance from listener");
		}

		Object user = invokeNoArg(minecraft, "ac");
		if (user == null) {
			throw new IllegalStateException("Failed to get User object from Minecraft");
		}

		Object profileIdObj = invokeNoArg(user, "b");
		if (!(profileIdObj instanceof UUID)) {
			throw new IllegalStateException("Failed to get profile UUID from User");
		}
		UUID profileId = (UUID) profileIdObj;

		Object accessTokenObj = invokeNoArg(user, "d");
		if (!(accessTokenObj instanceof String) || ((String) accessTokenObj).isEmpty()) {
			throw new IllegalStateException("Failed to get access token from User");
		}
		String accessToken = (String) accessTokenObj;

		Object services = invokeNoArg(minecraft, "as");
		if (services == null) {
			throw new IllegalStateException("Failed to get Services object from Minecraft");
		}

		Object sessionService = invokeNoArg(services, "c");
		if (sessionService == null) {
			throw new IllegalStateException("Failed to get MinecraftSessionService from Services");
		}

		Method joinServer = findMethod(sessionService.getClass(), "joinServer", 3);
		if (joinServer == null) {
			throw new NoSuchMethodException("MinecraftSessionService.joinServer(UUID,String,String) not found");
		}
		joinServer.invoke(sessionService, profileId, accessToken, nonce);
	}

	private static void sendNonceResponse(Object listenerObj, String nonce, String channel) throws Exception {
		sendRawPluginPayload(listenerObj, channel, nonce.getBytes(UTF_8));
	}

	private static void sendRawPluginPayload(Object listenerObj, String channel, byte[] payloadBytes) throws Exception {
		ClassLoader classLoader = listenerObj.getClass().getClassLoader();
		Class<?> identifierClass = Class.forName("amo", false, classLoader);
		Class<?> discardedPayloadClass = Class.forName("ace", false, classLoader);
		Class<?> customPayloadInterface = Class.forName("acd", false, classLoader);
		Class<?> serverboundCustomPayloadPacketClass = Class.forName("aby", false, classLoader);

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

	private static Method findSendMethod(Class<?> listenerClass, Class<?> packetClass) {
		for (Method method : listenerClass.getMethods()) {
			if (!"b".equals(method.getName()) || method.getParameterCount() != 1) {
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

	private static Object getFieldValue(Object target, String fieldName) throws IllegalAccessException {
		Field field = findField(target.getClass(), fieldName);
		if (field == null) {
			return null;
		}
		return field.get(target);
	}

	private static Method findMethod(Class<?> type, String name, int paramCount) {
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
				debug("writeBytes(byte[]) method not found on " + friendlyByteBufObj.getClass().getName());
				return;
			}
			writeBytesMethod.invoke(friendlyByteBufObj, bytes);
		} catch (Throwable ignored) {
			debug("writeBytes invoke failed: " + ignored);
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
