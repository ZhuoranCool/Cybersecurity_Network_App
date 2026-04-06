package main.as;

import java.io.File;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import main.common.Models;
import main.common.Persistence;
import main.common.SecurityUtil;

public class AuthorizationServer {
    public PrivateKey privateKey;
    public PublicKey publicKey;
    public final String publicKeyPath;
    public final String privateKeyPath;
    public static final int DEFAULT_PORT = 9000;
    public static final long DEFAULT_TOKEN_TTL_SEC = 3600L;

    public final Map<String, Models.User> users;
    public final Map<String, Models.UserAccess> accessByUser;
    public final Map<String, Models.TokenClaims> tokens;
    public final Map<String, Models.Course> courses;

    public final String usersPath;
    public final String accessPath;
    public final String tokensPath;
    public final String coursesPath;
    public final long tokenTtlSec;

    public AuthorizationServer(String usersPath, String accessPath, String tokensPath, String coursesPath,
            long tokenTtlSec, String publicKeyPath, String privateKeyPath) throws Exception {
        this.usersPath = usersPath;
        this.accessPath = accessPath;
        this.tokensPath = tokensPath;
        this.coursesPath = coursesPath;
        this.tokenTtlSec = tokenTtlSec;
        this.publicKeyPath = publicKeyPath;
        this.privateKeyPath = privateKeyPath;

        this.users = new ConcurrentHashMap<>(
                Persistence.loadOrDefault(usersPath, new ConcurrentHashMap<String, Models.User>())
        );
        this.accessByUser = new ConcurrentHashMap<>(
                Persistence.loadOrDefault(accessPath, new ConcurrentHashMap<String, Models.UserAccess>())
        );
        this.tokens = new ConcurrentHashMap<>(
                Persistence.loadOrDefault(tokensPath, new ConcurrentHashMap<String, Models.TokenClaims>())
        );
        this.courses = new ConcurrentHashMap<>(
                Persistence.loadOrDefault(coursesPath, new ConcurrentHashMap<String, Models.Course>())
        );

        File pubFile = new File(publicKeyPath);
        File privFile = new File(privateKeyPath);

        if (pubFile.exists() && privFile.exists()) {
            this.publicKey = SecurityUtil.loadPublicKey(publicKeyPath);
            this.privateKey = SecurityUtil.loadPrivateKey(privateKeyPath);
            System.out.println("[AS] Loaded existing RSA keypair.");
        } else {
            KeyPair kp = SecurityUtil.generateRSAKeyPair();
            this.publicKey = kp.getPublic();
            this.privateKey = kp.getPrivate();

            SecurityUtil.savePublicKey(this.publicKey, publicKeyPath);
            SecurityUtil.savePrivateKey(this.privateKey, privateKeyPath);

            System.out.println("[AS] Generated new RSA keypair.");
            System.out.println("[AS] Public key saved to " + publicKeyPath);
            System.out.println("[AS] Private key saved to " + privateKeyPath);
        }

        seedAdminIfEmpty();
    }

    private void seedAdminIfEmpty() {
        if (!users.isEmpty()) return;

        System.out.println("[AS] Seeding default admin account...");

        String username = "admin";
        String password = "admin123";

        users.put(username, new Models.User(
                username,
                SecurityUtil.bcryptHash(password),
                "admin@local"
        ));

        accessByUser.put(username, new Models.UserAccess(true, new ConcurrentHashMap<>()));

        try {
            flush();
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("[AS] Admin created -> username=admin password=admin123");
    }

    public synchronized void flush() throws Exception {
        Persistence.saveAtomic(new ConcurrentHashMap<>(users), usersPath);
        Persistence.saveAtomic(new ConcurrentHashMap<>(accessByUser), accessPath);
        Persistence.saveAtomic(new ConcurrentHashMap<>(tokens), tokensPath);
        Persistence.saveAtomic(new ConcurrentHashMap<>(courses), coursesPath);
    }

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        String usersPath = "data/as/users.db";
        String accessPath = "data/as/roles.db";
        String tokensPath = "data/as/tokens.db";
        String coursesPath = "data/as/courses.db";
        String publicKeyPath = "data/keys/as_public.key";
        String privateKeyPath = "data/keys/as_private.key";
        long ttl = DEFAULT_TOKEN_TTL_SEC;

        try {
           AuthorizationServer server = new AuthorizationServer(
                    usersPath, accessPath, tokensPath, coursesPath, ttl,
                    publicKeyPath, privateKeyPath
            );

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    server.flush();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }));

            try (ServerSocket ss = new ServerSocket(port)) {
                System.out.println("[AS] Listening on port " + port);

                while (true) {
                    Socket sock = ss.accept();
                    new AuthorizationWorker(sock, server).start();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}