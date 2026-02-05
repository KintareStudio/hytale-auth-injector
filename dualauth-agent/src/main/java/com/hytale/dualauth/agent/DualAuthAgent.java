package com.hytale.dualauth.agent;

import com.hytale.dualauth.agent.transformers.*;
import com.hytale.dualauth.agent.transformers.LoggingTransformer;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Properties;
import java.io.InputStream;

import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * PRODUCTION-READY DUALAUTH AGENT (JDK 25)
 * 
 * This agent intercepts Hytale Server auth classes to enable:
 * 1. Dual JWKS merging (Official + F2P + Dynamic)
 * 2. Omni-Auth bypass (embedded JWK verification)
 * 3. URL routing based on issuer
 * 4. Token management for F2P/Omni clients
 */
public class DualAuthAgent {
    public static final String VERSION = loadVersion();

    private static String loadVersion() {
        try (InputStream is = DualAuthAgent.class.getResourceAsStream("/version.properties")) {
            Properties prop = new Properties();
            if (is != null) {
                prop.load(is);
                return prop.getProperty("version", "1.0.0-UNKNOWN");
            }
        } catch (Exception e) {
            // Fallback
        }
        return "1.0.0-DEV";
    }

    public static void main(String[] args) {
        if (args.length > 0 && (args[0].equals("--version") || args[0].equals("-v"))) {
            System.out.println("DualAuth Agent version: " + VERSION);
        } else {
            System.out.println("DualAuth Agent v" + VERSION);
            System.out.println("Usage: java -javaagent:dualauth-agent.jar -jar HytaleServer.jar");
            System.out.println("   or: java -jar dualauth-agent.jar --version");
        }
    }

    public static void premain(String args, Instrumentation inst) {
        // Handle --version in agent arguments
        if (args != null && (args.contains("version") || args.contains("-v"))) {
            System.out.println("DualAuth Agent version: " + VERSION);
            if (args.equals("version") || args.equals("--version") || args.equals("-v")) {
                return; // Exit premain if only version was requested
            }
        }

        // Enable experimental mode for newer Java versions
        System.setProperty("net.bytebuddy.experimental", "true");
        
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║            DualAuth ByteBuddy Agent v" + padRight(VERSION, 24) + "║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                               ║");
        System.out.println("║   F2P Domain: " + padRight(DualAuthConfig.F2P_DOMAIN, 47) + "║");
        System.out.println("║   F2P Session URL: " + padRight(DualAuthConfig.F2P_SESSION_URL, 42) + "║");
        System.out.println("║   Official URL: " + padRight(DualAuthConfig.OFFICIAL_SESSION_URL, 45) + "║");
        System.out.println("║   Trust All Issuers: " + padRight(String.valueOf(DualAuthConfig.TRUST_ALL_ISSUERS), 40) + "║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // Start async Warmup immediately (don't block main thread)
        DualAuthWarmup.start();

        new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
            // Add listener to see what's being transformed
            .with(new AgentBuilder.Listener.Adapter() {
                @Override
                public void onTransformation(TypeDescription typeDescription, ClassLoader classLoader,
                        JavaModule module, boolean loaded, DynamicType dynamicType) {
                    System.out.println("[DualAuth] ✓ TRANSFORMED: " + typeDescription.getName());
                }

                @Override
                public void onError(String typeName, ClassLoader classLoader, JavaModule module, boolean loaded, Throwable throwable) {
                    System.err.println("[DualAuth] ✗ ERROR transforming " + typeName + ": " + throwable.getMessage());
                    throwable.printStackTrace();
                }
            })
            .ignore(ElementMatchers.nameStartsWith("net.bytebuddy.")
               .or(ElementMatchers.nameStartsWith("jdk."))
               .or(ElementMatchers.nameStartsWith("java."))
               .or(ElementMatchers.nameStartsWith("sun."))
               .or(ElementMatchers.nameStartsWith("com.hytale.dualauth."))) // Don't transform ourselves!
            
            // 1. JWT Logic (Validator & Keys)
            .type(named("com.hypixel.hytale.server.core.auth.JWTValidator"))
            .transform(new JWTValidatorTransformer())

            // 2. Session Logic (Auth Grants & URL Routing & JWKS Fetching)
            .type(named("com.hypixel.hytale.server.core.auth.SessionServiceClient"))
            .transform(new SessionServiceClientTransformer())

            // 3. Network Packet Logic (AuthGrant Serialization)
            .type(named("com.hypixel.hytale.protocol.packets.auth.AuthGrant"))
            .transform(new AuthGrantTransformer())

            // 4. Handshake Logic (Login processing)
            .type(nameContains("HandshakeHandler"))
            .transform(new HandshakeHandlerTransformer())

            // 5. Manager Logic (Native Token Capture)
            .type(named("com.hypixel.hytale.server.core.auth.ServerAuthManager"))
            .transform(new ServerAuthManagerTransformer())
            
            // 6. Logging Enhancement (Complete replacement of logging system)
            .type(named("com.hypixel.hytale.logger.backend.HytaleLogFormatter"))
            .transform(new LoggingTransformer())
            
            .installOn(inst);
            
        System.out.println("[DualAuth] ByteBuddy Agent Installed Successfully.");
        System.out.println("[DualAuth] Waiting for Hytale Server classes to load...");
    }

    private static String padRight(String s, int length) {
        if (s == null) s = "null";
        if (s.length() >= length) return s.substring(0, length);
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < length) {
            sb.append(' ');
        }
        return sb.toString();
    }
}
