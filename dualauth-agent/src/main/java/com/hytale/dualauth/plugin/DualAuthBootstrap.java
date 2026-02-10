package com.hytale.dualauth.plugin;

import com.hypixel.hytale.server.core.plugin.JavaPlugin;
import com.hypixel.hytale.server.core.plugin.JavaPluginInit;
import net.bytebuddy.agent.ByteBuddyAgent;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.jar.JarFile;

/**
 * BRIDGE CLASS: This runs inside Hytale's "ThirdPartyPlugin" ClassLoader.
 * 
 * CONFLICT PREVENTION STRATEGY:
 * 1. Checks 'dualauth.agent.active' System Property immediately.
 * 2. If true (Agent loaded via -javaagent), it logs "Passive Mode" and stops.
 * 3. If false, it performs the Dynamic Attach (Injection).
 */
public class DualAuthBootstrap extends JavaPlugin {

    public DualAuthBootstrap(JavaPluginInit init) {
        super(init);
    }

    @Override
    protected void setup() {
        // Verificar si el agente ya está corriendo (cargado al inicio con -javaagent)
        if (System.getProperty("dualauth.agent.active") != null) {
            System.out.println("[DualAuth] Plugin Wrapper: Agent is ALREADY ACTIVE via -javaagent flag.");
            System.out.println("[DualAuth] Plugin Wrapper: Entering PASSIVE mode (no action taken).");
            return; // EXITOSA, pero no hace nada.
        }

        System.out.println("[DualAuth] Plugin Wrapper: Agent not detected. Initializing Dynamic Attach...");
        injectAgent();
    }

    @Override
    protected void start() {
        // Nada que hacer aquí. La lógica reside enteramente en el Agente (System ClassLoader).
    }

    private void injectAgent() {
        try {
            // Doble verificación por seguridad
            if (System.getProperty("dualauth.agent.active") != null) return;

            // 1. Instalar ByteBuddy Agent para obtener Instrumentation
            Instrumentation inst = ByteBuddyAgent.install();

            // 2. Obtener la ubicación de ESTE archivo jar
            File currentJar = new File(getClass().getProtectionDomain().getCodeSource().getLocation().toURI());

            // 3. INYECTAR EN SYSTEM CLASSLOADER
            // Esto es vital. Movemos el JAR del "PluginClassLoader" al "SystemClassLoader".
            inst.appendToSystemClassLoaderSearch(new JarFile(currentJar));

            // 4. TRAMPOLÍN DE REFLEXIÓN
            // Usamos el SystemClassLoader para cargar la clase del Agente.
            // Si usáramos DualAuthAgent.class directamente, usaríamos el PluginClassLoader, causando LinkageError.
            ClassLoader systemLoader = ClassLoader.getSystemClassLoader();
            
            Class<?> agentClass = systemLoader.loadClass("com.hytale.dualauth.agent.DualAuthAgent");
            Method agentMainMethod = agentClass.getMethod("agentmain", String.class, Instrumentation.class);
            
            // 5. Ejecutar el agente en el contexto del Sistema
            agentMainMethod.invoke(null, "plugin-mode", inst);
            
            // 6. Marcar éxito
            System.setProperty("dualauth.agent.active", "true");

        } catch (Throwable e) {
            System.err.println("[DualAuth] CRITICAL: Failed to attach agent dynamically!");
            System.err.println("[DualAuth] Please try adding the flag: -XX:+EnableDynamicAgentLoading");
            e.printStackTrace();
        }
    }
}
