/*
 * Copyright (C) 2026  PotatoLauncher contributors
 */
package moe.yushi.authlibinjector.transform.support;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class PotatoAuth121Profiles {

	private static final List<PotatoAuth121Profile> PROFILES;

	static {
		List<PotatoAuth121Profile> profiles = new ArrayList<PotatoAuth121Profile>();
		profiles.add(new PotatoAuth121Profile("1.21", "aak", "a", "a", "b", "fzc", "a", "fzg", "a", "zn", "b", "aab", "aaj", "akr", "vw", "fgo", "fhb", "alm", "X", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.1", "aak", "a", "a", "b", "fzc", "a", "fzg", "a", "zn", "b", "aab", "aaj", "akr", "vw", "fgo", "fhb", "alm", "X", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.2", "abg", "a", "a", "b", "gfg", "a", "gfk", "a", "aaj", "b", "aax", "abf", "alz", "ws", "fmf", "fmr", "amu", "X", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.3", "abg", "a", "a", "b", "gfh", "a", "gfl", "a", "aaj", "b", "aax", "abf", "alz", "ws", "fmg", "fms", "amu", "X", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.4", "aaa", "a", "a", "b", "gfx", "a", "ggb", "a", "zd", "b", "zr", "zz", "akv", "vl", "flk", "flw", "alq", "X", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.5", "aau", "a", "a", "b", "gll", "a", "glp", "a", "zx", "b", "aal", "aat", "alr", "vy", "fqq", "frc", "amm", "X", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.6", "abf", "a", "a", "b", "grg", "a", "grk", "a", "aag", "b", "aaw", "abe", "ame", "wg", "fud", "fup", "amz", "Y", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.7", "abf", "a", "a", "b", "grg", "a", "grk", "a", "aag", "b", "aaw", "abe", "ame", "wg", "fud", "fup", "amz", "Y", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.8", "abf", "a", "a", "b", "grh", "a", "grl", "a", "aag", "b", "aaw", "abe", "ame", "wg", "fue", "fuq", "amz", "Y", null, "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.9", "abu", "a", "a", "b", "gzi", "a", "gzo", "a", "aay", "b", "abo", "abt", "amj", "wn", "fzz", "gal", "ane", "ad", "as", "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.10", "abu", "a", "a", "b", "gzi", "a", "gzo", "a", "aay", "b", "abo", "abt", "amj", "wn", "fzz", "gal", "ane", "ad", "as", "b", "d", "c"));
		profiles.add(new PotatoAuth121Profile("1.21.11", "ace", "a", "a", "b", "hia", "a", "hig", "a", "abi", "b", "aby", "acd", "amo", "wx", "gfj", "gfx", "ano", "ac", "as", "b", "d", "c"));
		PROFILES = Collections.unmodifiableList(profiles);
	}

	public static List<PotatoAuth121Profile> all() {
		return PROFILES;
	}

	public static PotatoAuth121Profile findByDiscardedPayloadClass(String className) {
		return findFirst(profile -> Objects.equals(profile.discardedPayloadClass(), className));
	}

	public static PotatoAuth121Profile findByClientCommonPacketListenerClass(String className) {
		return findFirst(profile -> Objects.equals(profile.clientCommonPacketListenerClass(), className));
	}

	public static PotatoAuth121Profile findByClientPlayPacketListenerClass(String className) {
		return findFirst(profile -> Objects.equals(profile.clientPlayPacketListenerClass(), className));
	}

	public static PotatoAuth121Profile findByAnyClassName(String className) {
		return findFirst(profile ->
			Objects.equals(profile.discardedPayloadClass(), className)
				|| Objects.equals(profile.clientCommonPacketListenerClass(), className)
				|| Objects.equals(profile.clientPlayPacketListenerClass(), className)
				|| Objects.equals(profile.clientboundCustomPayloadPacketClass(), className)
				|| Objects.equals(profile.serverboundCustomPayloadPacketClass(), className)
				|| Objects.equals(profile.customPacketPayloadClass(), className)
				|| Objects.equals(profile.minecraftClass(), className)
				|| Objects.equals(profile.userClass(), className)
				|| Objects.equals(profile.servicesClass(), className)
		);
	}

	private static PotatoAuth121Profile findFirst(ProfileMatcher matcher) {
		for (PotatoAuth121Profile profile : PROFILES) {
			if (matcher.matches(profile)) {
				return profile;
			}
		}
		return null;
	}

	private interface ProfileMatcher {
		boolean matches(PotatoAuth121Profile profile);
	}

	private PotatoAuth121Profiles() {}
}
