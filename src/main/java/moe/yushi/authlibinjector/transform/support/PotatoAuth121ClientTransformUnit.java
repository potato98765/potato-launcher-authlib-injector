/*
 * Copyright (C) 2026  PotatoLauncher contributors
 */
package moe.yushi.authlibinjector.transform.support;

import static org.objectweb.asm.Opcodes.ALOAD;
import static org.objectweb.asm.Opcodes.ARETURN;
import static org.objectweb.asm.Opcodes.ASM9;
import static org.objectweb.asm.Opcodes.DUP;
import java.util.Optional;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import moe.yushi.authlibinjector.transform.TransformContext;
import moe.yushi.authlibinjector.transform.TransformUnit;

/**
 * Minecraft 1.21.x hooks:
 * - Preserve unknown custom payload bytes in DiscardedPayload
 * - Observe incoming custom payload packets in client common/play listeners
 */
public class PotatoAuth121ClientTransformUnit implements TransformUnit {

	@Override
	public Optional<ClassVisitor> transform(ClassLoader classLoader, String className, ClassVisitor writer, TransformContext ctx) {
		PotatoAuth121Profile discardedProfile = PotatoAuth121Profiles.findByDiscardedPayloadClass(className);
		if (discardedProfile != null) {
			return Optional.of(transformDiscardedPayload(writer, ctx, discardedProfile));
		}

		PotatoAuth121Profile commonProfile = PotatoAuth121Profiles.findByClientCommonPacketListenerClass(className);
		if (commonProfile != null) {
			return Optional.of(transformClientCommonPacketListener(writer, ctx, commonProfile));
		}

		PotatoAuth121Profile playProfile = PotatoAuth121Profiles.findByClientPlayPacketListenerClass(className);
		if (playProfile != null) {
			return Optional.of(transformClientPlayPacketListener(writer, ctx, playProfile));
		}

		return Optional.empty();
	}

	private ClassVisitor transformDiscardedPayload(ClassVisitor writer, TransformContext ctx, PotatoAuth121Profile profile) {
		return new ClassVisitor(ASM9, writer) {
			@Override
			public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
				MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

				if (profile.discardedReadMethod().equals(name) && profile.discardedReadDescriptor().equals(descriptor)) {
					return new MethodVisitor(ASM9, mv) {
						@Override
						public void visitCode() {
							super.visitCode();
							ctx.markModified();

							super.visitVarInsn(ALOAD, 2);
							ctx.invokeCallback(mv, PotatoAuthClientBridge.class, "captureIncomingDiscardedPayloadBytes");
						}

						@Override
						public void visitInsn(int opcode) {
							if (opcode == ARETURN) {
								super.visitInsn(DUP);
								super.visitVarInsn(ALOAD, 1);
								super.visitVarInsn(ALOAD, 2);
								ctx.invokeCallback(mv, PotatoAuthClientBridge.class, "completeIncomingDiscardedPayload");
							}
							super.visitInsn(opcode);
						}
					};
				}

				if (profile.discardedWriteMethod().equals(name) && profile.discardedWriteDescriptor().equals(descriptor)) {
					return new MethodVisitor(ASM9, mv) {
						@Override
						public void visitCode() {
							super.visitCode();
							ctx.markModified();

							super.visitVarInsn(ALOAD, 0);
							super.visitVarInsn(ALOAD, 1);
							ctx.invokeCallback(mv, PotatoAuthClientBridge.class, "writeOutgoingDiscardedPayloadBytes");
						}
					};
				}

				return mv;
			}
		};
	}

	private ClassVisitor transformClientCommonPacketListener(ClassVisitor writer, TransformContext ctx, PotatoAuth121Profile profile) {
		return new ClassVisitor(ASM9, writer) {
			@Override
			public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
				MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

				if (profile.clientCommonHandlePacketMethod().equals(name) && profile.clientCommonHandlePacketDescriptor().equals(descriptor)) {
					return new MethodVisitor(ASM9, mv) {
						@Override
						public void visitCode() {
							super.visitCode();
							ctx.markModified();

							super.visitVarInsn(ALOAD, 0);
							super.visitVarInsn(ALOAD, 1);
							ctx.invokeCallback(mv, PotatoAuthClientBridge.class, "onClientboundCustomPayloadPacket");
						}
					};
				}

				return mv;
			}
		};
	}

	private ClassVisitor transformClientPlayPacketListener(ClassVisitor writer, TransformContext ctx, PotatoAuth121Profile profile) {
		return new ClassVisitor(ASM9, writer) {
			@Override
			public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
				MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

				if (profile.clientPlayHandlePayloadMethod().equals(name) && profile.clientPlayHandlePayloadDescriptor().equals(descriptor)) {
					return new MethodVisitor(ASM9, mv) {
						@Override
						public void visitCode() {
							super.visitCode();
							ctx.markModified();

							super.visitVarInsn(ALOAD, 0);
							super.visitVarInsn(ALOAD, 1);
							ctx.invokeCallback(mv, PotatoAuthClientBridge.class, "onClientboundCustomPayload");
						}
					};
				}

				return mv;
			}
		};
	}

	@Override
	public String toString() {
		return "PotatoAuth 1.21.x Client Transform";
	}
}
