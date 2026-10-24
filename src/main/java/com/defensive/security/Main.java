package com.defensive.security;

import com.defensive.security.config.DatabaseConfig;
import com.defensive.security.web.*;
import com.sun.net.httpserver.HttpServer;

import java.awt.Desktop;
import java.io.IOException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.concurrent.Executors;

/**
 * Main - Application Entry Point
 * 
 * Project: Defensive Guide to SQL Injection and Database Security
 * Purpose: College Value Added Course (VAC) Cybersecurity Demonstration
 * 
 * Features:
 *  - Lightweight embedded HTTP server (JDK com.sun.net.httpserver)
 *  - Automatic MySQL connectivity detection and schema verification
 *  - Fallback safe demo mode for zero-configuration demonstration
 *  - Automatic browser launch for seamless presentation demo
 */
public class Main {

    public static void main(String[] args) {
        printBanner();

        // 1. Check and report MySQL database status
        System.out.println(">>> Checking MySQL Database Connectivity...");
        boolean dbConnected = DatabaseConfig.checkConnection();
        if (dbConnected) {
            System.out.println(">>> [SUCCESS] Connected to MySQL Database at: " + DatabaseConfig.getDbUrl());
            System.out.println(">>> Verifying database schema and initial security tables...");
            DatabaseConfig.ensureSchema();
            System.out.println(">>> Database schema is ready.");
        } else {
            System.out.println(">>> [NOTICE] MySQL Server is currently unreachable (" + DatabaseConfig.getLastConnectionError() + ")");
            System.out.println(">>> Running in [SAFE INTERACTIVE DEMO MODE].");
            System.out.println(">>> All interactive simulators, security checklist, and quiz work 100% smoothly offline!");
            System.out.println(">>> (To connect MySQL later: Start MySQL on port 3306 and run database.sql)\n");
        }

        // 2. Start HTTP Server with automatic port fallback
        int preferredPort = DatabaseConfig.getServerPort();
        HttpServer server = null;
        int activePort = preferredPort;

        for (int p = preferredPort; p <= preferredPort + 5; p++) {
            try {
                server = HttpServer.create(new InetSocketAddress(p), 0);
                activePort = p;
                break;
            } catch (BindException e) {
                System.out.println(">>> Port " + p + " is occupied, attempting port " + (p + 1) + "...");
            } catch (IOException e) {
                System.err.println(">>> Failed to bind server: " + e.getMessage());
                return;
            }
        }

        if (server == null) {
            System.err.println(">>> ERROR: Could not bind to any port between " + preferredPort + " and " + (preferredPort + 5));
            return;
        }

        // 3. Register HTTP routes
        // REST API Endpoints
        server.createContext("/api/status", new ApiStatusHandler());
        server.createContext("/api/login-demo", new ApiLoginDemoHandler());
        server.createContext("/api/quiz", new ApiQuizHandler());
        server.createContext("/api/audit-logs", new ApiAuditLogHandler());

        // Static Frontend Files (HTML, CSS, JS, etc.)
        server.createContext("/", new StaticFileHandler());

        // Multi-threaded request execution
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();

        final String appUrl = "http://localhost:" + activePort + "/";

        System.out.println("==================================================================");
        System.out.println("🚀 WEB APPLICATION STARTED SUCCESSFULLY!");
        System.out.println("👉 Access the application in your browser at:");
        System.out.println("   " + appUrl);
        System.out.println("==================================================================");
        System.out.println("Press Ctrl + C in the console to stop the server.\n");

        // 4. Automatically open default browser for seamless evaluation
        launchBrowser(appUrl);

        // Add clean shutdown hook
        final HttpServer finalServer = server;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n>>> Shutting down Defensive Security Web Server...");
            finalServer.stop(1);
            System.out.println(">>> Server stopped safely. Goodbye!");
        }));
    }

    private static void launchBrowser(String url) {
        new Thread(() -> {
            try {
                // Short delay to ensure server socket is fully accepting requests
                Thread.sleep(800);
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                    Desktop.getDesktop().browse(new URI(url));
                }
            } catch (Exception e) {
                // Headless or restricted environment - fallback gracefully
                System.out.println(">>> Note: Open " + url + " manually in any web browser.");
            }
        }).start();
    }

    private static void printBanner() {
        System.out.println("==================================================================");
        System.out.println("  ____  ______ ______ ______ _   _  _____ _______      ________ ");
        System.out.println(" |  _ \\|  ____|  ____|  ____| \\ | |/ ____|_   _\\ \\    / /  ____|");
        System.out.println(" | |_) | |__  | |__  | |__  |  \\| | (___   | |  \\ \\  / /| |__   ");
        System.out.println(" |  _ <|  __| |  __| |  __| | . ` |\\___ \\  | |   \\ \\/ / |  __|  ");
        System.out.println(" | |_) | |____| |____| |____| |\\  |____) |_| |_   \\  /  | |____ ");
        System.out.println(" |____/|______|______|______|_| \\_|_____/|_____|   \\/   |______|");
        System.out.println("                                                                ");
        System.out.println("   DEFENSIVE GUIDE TO SQL INJECTION AND DATABASE SECURITY       ");
        System.out.println("   Academic Mini-Project / Value Added Course in Cybersecurity ");
        System.out.println("==================================================================");
    }
}
