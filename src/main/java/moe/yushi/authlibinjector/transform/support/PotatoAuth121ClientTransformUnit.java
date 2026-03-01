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
 * Minecraft 1.21.11 specific hooks:
 * - Preserve unknown custom payload bytes in {@code ace} (DiscardedPayload)
 * - Observe incoming custom payload packets in {@code hia} (ClientCommonPacketListenerImpl)
 */
public class PotatoAuth121ClientTransformUnit implements TransformUnit {

	@Override
	public Optional<ClassVisitor> transform(ClassLoader classLoader, String className, ClassVisitor writer, TransformContext ctx) {
		if ("ace".equals(className)) {
			return Optional.of(transformDiscardedPayload(writer, ctx));
		}
		if ("hia".equals(className)) {
			return Optional.of(transformClientCommonPacketListener(writer, ctx));
		}
		if ("hig".equals(className)) {
			return Optional.of(transformClientPlayPacketListener(writer, ctx));
		}
		return Optional.empty();
	}

	private ClassVisitor transformDiscardedPayload(ClassVisitor writer, TransformContext ctx) {
		return new ClassVisitor(ASM9, writer) {
			@Override
			public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
				MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

				// private static ace a(int, amo, wx)
				if ("a".equals(name) && "(ILamo;Lwx;)Lace;".equals(descriptor)) {
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

				// private static void a(ace, wx)
				if ("a".equals(name) && "(Lace;Lwx;)V".equals(descriptor)) {
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

	private ClassVisitor transformClientCommonPacketListener(ClassVisitor writer, TransformContext ctx) {
		return new ClassVisitor(ASM9, writer) {
			@Override
			public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
				MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

				// void a(abi) = handleCustomPayload(ClientboundCustomPayloadPacket)
				if ("a".equals(name) && "(Labi;)V".equals(descriptor)) {
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

	private ClassVisitor transformClientPlayPacketListener(ClassVisitor writer, TransformContext ctx) {
		return new ClassVisitor(ASM9, writer) {
			@Override
			public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
				MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

				// void a(acd) = handleCustomPayload(CustomPacketPayload) in play listener
				if ("a".equals(name) && "(Lacd;)V".equals(descriptor)) {
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
		return "PotatoAuth 1.21.11 Client Transform";
	}
}
