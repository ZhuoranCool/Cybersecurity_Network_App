package main.rs;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.SecretKey;

import main.common.SecureEnvelope;
import com.fasterxml.jackson.databind.ObjectMapper;

import main.common.ErrorCodes;
import main.common.MessageTypes;
import main.common.Models;
import main.common.NetMessage;
import main.common.Persistence;
import main.common.SecurityUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

public class ResourceServer {
    private static final long AUTH_TIMESTAMP_SKEW_MS = 5 * 60 * 1000L;

    private static final long CERT_TIMESTAMP_SKEW_MS=120*60*1000L;

    private final String id;

    public final PublicKey publicKey;
    public final PrivateKey privateKey;
    
    private final int listenPort;
    private final ExecutorService pool = Executors.newCachedThreadPool();

    private final String heartbeatHost;
    private final int heartbeatPort;

    private final String statePath;
    private final String publicKeyPath = "data/keys/rs_public.key";
    private final String privateKeyPath = "data/keys/rs_private.key";
    private final ObjectMapper mapper = new ObjectMapper();

    private PublicKey asPublicKey;
    private RSState state;

    private SecretKey sessionAESKey = null;
    private String clientNonce=null;
    private String rsNonce=null;
    private SecretKey preMasterKey = null;
    private byte[] handshakeTranscript = null;

    public ResourceServer(int listenPort, String statePath,
                          String heartbeatHost, int heartbeatPort) {
        this.listenPort = listenPort;
        this.statePath = statePath;
        this.heartbeatHost = heartbeatHost;
        this.heartbeatPort = heartbeatPort;

        try {
            java.io.File pubFile = new java.io.File(publicKeyPath);
            java.io.File privFile = new java.io.File(privateKeyPath);

            if (pubFile.exists() && privFile.exists()) {
                this.publicKey = SecurityUtil.loadPublicKey(publicKeyPath);
                this.privateKey = SecurityUtil.loadPrivateKey(privateKeyPath);
                System.out.println("[RS] Loaded existing RSA keypair.");
            } else {
                KeyPair kp = SecurityUtil.generateRSAKeyPair();
                this.publicKey = kp.getPublic();
                this.privateKey = kp.getPrivate();

                SecurityUtil.savePublicKey(this.publicKey, publicKeyPath);
                SecurityUtil.savePrivateKey(this.privateKey, privateKeyPath);

                System.out.println("[RS] Generated new RSA keypair.");
                System.out.println("[RS] Public key saved to " + publicKeyPath);
                System.out.println("[RS] Private key saved to " + privateKeyPath);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to init RS keypair", e);
        }
        this.id = java.util.UUID.randomUUID().toString();
    }

    public void start() throws Exception {
        this.asPublicKey = loadASPublicKey("data/keys/as_public.key");
        this.state = Persistence.loadOrDefault(statePath, new RSState());
        System.out.println("[RS] Loaded state from " + statePath + " (posts=" + state.posts.size() + ")");

        if (heartbeatHost != null) {
            pool.submit(new ResourceServerSignalSender(heartbeatHost, heartbeatPort, listenPort));
        }

        try (ServerSocket serverSocket = new ServerSocket(listenPort)) {
            System.out.println("[RS] Listening on port " + listenPort);

            while (true) {
                Socket client = serverSocket.accept();
                pool.submit(() -> handleClient(client));
            }
        }
    }

    private NetMessage handleClientHello(NetMessage req) throws Exception {
        String version = s(req.payload.get("version"));
        String nc = s(req.payload.get("Nc"));
        String clientEphemeralPublicKeyB64 = s(req.payload.get("clientEphemeralPublicKey"));

        Object algObj = req.payload.get("supportedAlgorithms");
        List<String> supportedAlgorithms = new ArrayList<>();
        if (algObj instanceof List<?>) {
            for (Object x : (List<?>) algObj) {
                supportedAlgorithms.add(String.valueOf(x));
            }
        }

        if (isBlank(version) || isBlank(nc) || isBlank(clientEphemeralPublicKeyB64)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing ClientHello fields");
        }

        // choose an algorithm
        List<String> selectedAlgorithms = new ArrayList<>();
        if (supportedAlgorithms.contains("RSA")) selectedAlgorithms.add("RSA");
        if (supportedAlgorithms.contains("SHA256")) selectedAlgorithms.add("SHA256");

        if (selectedAlgorithms.isEmpty()) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "no mutually supported algorithms");
        }

        // server nonce and ephemeral key for this handshake
        String ns = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        KeyPair eph = SecurityUtil.generateRSAKeyPair();
        String serverEphemeralPublicKeyB64 = Base64.getEncoder().encodeToString(eph.getPublic().getEncoded());

        // nonce
        this.clientNonce = nc;
        this.rsNonce = ns;

        String payload = buildServerHelloSigningPayload(
                this.id,
                version,
                supportedAlgorithms,
                nc,
                clientEphemeralPublicKeyB64,
                version,
                selectedAlgorithms,
                ns,
                serverEphemeralPublicKeyB64
        );

        String payloadHashHex = SecurityUtil.sha256(payload);
        byte[] signingPayload = payloadHashHex.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        this.handshakeTranscript = buildHandshakeTranscript(
                this.id,
                version,
                supportedAlgorithms,
                nc,
                clientEphemeralPublicKeyB64,
                version,
                selectedAlgorithms,
                ns,
                serverEphemeralPublicKeyB64
        );

        byte[] sig = SecurityUtil.rsaSignPSS(signingPayload, privateKey);
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        NetMessage resp = NetMessage.ok(req.requestId);
        resp.type = MessageTypes.RS_SERVER_HELLO_RESP;
        resp.payload.put("version", version);
        resp.payload.put("selectedAlgorithms", selectedAlgorithms);
        resp.payload.put("Ns", ns);
        resp.payload.put("serverEphemeralPublicKey", serverEphemeralPublicKeyB64);
        resp.payload.put("serverSignature", sigB64);
        resp.payload.put("RS_ID", this.id);

        return resp;
    }

    private String buildServerHelloSigningPayload(
        String rsId,
        String clientVersion,
        List<String> supportedAlgorithms,
        String nc,
        String clientEphemeralPublicKeyB64,
        String serverVersion,
        List<String> selectedAlgorithms,
        String ns,
        String serverEphemeralPublicKeyB64
    ) {
        return
                "RS_ID=" + rsId +
                "|ClientVersion=" + clientVersion +
                "|SupportedAlgorithms=" + String.join(",", supportedAlgorithms) +
                "|Nc=" + nc +
                "|ClientEphemeralPublicKey=" + clientEphemeralPublicKeyB64 +
                "|ServerVersion=" + serverVersion +
                "|SelectedAlgorithms=" + String.join(",", selectedAlgorithms) +
                "|Ns=" + ns +
                "|ServerEphemeralPublicKey=" + serverEphemeralPublicKeyB64;
    }

    //public for test
    public SecretKey deriveSessionKey(SecretKey preMasterKey, String nc, String ns) throws Exception {
        String seed = nc + "|" + ns;
        String hex = SecurityUtil.sha256(
                Base64.getEncoder().encodeToString(preMasterKey.getEncoded()) + "|" + seed
        );

        byte[] keyBytes = java.util.Arrays.copyOf(
                hex.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                32
        );

        return new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
    }

    // public for test
    public String computeFinished(String label, SecretKey sessionKey, byte[] transcriptBytes) throws Exception {
        String transcriptB64 = Base64.getEncoder().encodeToString(transcriptBytes);
        String keyB64 = Base64.getEncoder().encodeToString(sessionKey.getEncoded());

        String material = label + "|" + keyB64 + "|" + transcriptB64;
        return SecurityUtil.sha256(material);
    }

    private byte[] buildHandshakeTranscript(
        String rsId,
        String clientVersion,
        List<String> supportedAlgorithms,
        String nc,
        String clientEphemeralPublicKeyB64,
        String serverVersion,
        List<String> selectedAlgorithms,
        String ns,
        String serverEphemeralPublicKeyB64
    ) {
        String transcript =
                "RS_ID=" + rsId +
                "|ClientVersion=" + clientVersion +
                "|SupportedAlgorithms=" + String.join(",", supportedAlgorithms) +
                "|Nc=" + nc +
                "|ClientEphemeralPublicKey=" + clientEphemeralPublicKeyB64 +
                "|ServerVersion=" + serverVersion +
                "|SelectedAlgorithms=" + String.join(",", selectedAlgorithms) +
                "|Ns=" + ns +
                "|ServerEphemeralPublicKey=" + serverEphemeralPublicKeyB64;

        return transcript.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private NetMessage handleClientKey(NetMessage req) throws Exception {
        String encryptedPreMasterB64 = s(req.payload.get("encryptedPreMaster"));
        String clientFinished = s(req.payload.get("clientFinished"));

        if (isBlank(encryptedPreMasterB64) || isBlank(clientFinished)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing client key exchange fields");
        }

        byte[] encryptedPreMaster = Base64.getDecoder().decode(encryptedPreMasterB64);
        byte[] preMasterRaw = SecurityUtil.rsaDecryptOAEP(encryptedPreMaster, privateKey);
        this.preMasterKey = new javax.crypto.spec.SecretKeySpec(preMasterRaw, "AES");

        this.sessionAESKey = deriveSessionKey(preMasterKey, clientNonce, rsNonce);

        String expectedClientFinished = computeFinished(
                "client finished",
                sessionAESKey,
                handshakeTranscript
        );

        if (!Objects.equals(clientFinished, expectedClientFinished)) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "client Finished verification failed");
        }

        String serverFinished = computeFinished(
                "server finished",
                sessionAESKey,
                handshakeTranscript
        );

        NetMessage resp = NetMessage.ok(req.requestId);
        resp.type = MessageTypes.RS_FINISHED_RESP;
        resp.payload.put("serverFinished", serverFinished);
        return resp;
    }

    private void handleClient(Socket socket) {
        System.out.println("[RS] Client connected: " + socket.getRemoteSocketAddress());

        try (
                Socket s = socket;
                ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(s.getInputStream())
        ) {
            while (true) {
                Object obj = in.readObject();
                NetMessage req;
                boolean isSecureRequest = false;
                
                if (obj instanceof NetMessage) {
                    req = (NetMessage) obj;
                } else if (obj instanceof SecureEnvelope env) {
                    //handle secure envelope using instance session
                    isSecureRequest = true;
                    if (sessionAESKey == null) {
                        System.out.println("[RS] Received secure message but no session established");
                        break;
                    }
                    
                    byte[] plaintext = SecurityUtil.aesGcmDecrypt(env.ciphertext, sessionAESKey, env.iv);
                    req = mapper.readValue(plaintext, NetMessage.class);
                } else {
                    break;
                }

                NetMessage resp = route(req);

                if (isSecureRequest) {
                    //wrap response in SecureEnvelope for secure requests
                    byte[] respPlaintext = mapper.writeValueAsBytes(resp);
                    byte[] respIv = SecurityUtil.randomBytes(12);
                    byte[] respCiphertext = SecurityUtil.aesGcmEncrypt(respPlaintext, sessionAESKey, respIv);
                    SecureEnvelope respEnv = new SecureEnvelope(respIv, respCiphertext);
                    out.writeObject(respEnv);
                } else {
                    out.writeObject(resp);
                }
                out.flush();
            }
        } catch (Exception e) {
            System.out.println("[RS] Client handler ended: " + e.getMessage());
        }
    }

    private String key(String course, String title) {
        return course + "::" + title;
    }

    private String norm(String s) {
        return s == null ? "" : s.trim().toLowerCase();
    }

    private boolean isValidTag(String t) {
        t = norm(t);
        return t.equals("assignment") || t.equals("test") || t.equals("project");
    }

    private boolean enrolledInCourse(Models.TokenClaims claims, String course) {
        return claims != null
                && claims.courseRoles != null
                && claims.courseRoles.containsKey(course);
    }

    private String roleInCourse(Models.TokenClaims claims, String course) {
        if (claims == null || claims.courseRoles == null) return null;
        return claims.courseRoles.get(course);
    }

    private boolean canDeletePost(Models.TokenClaims claims, String course) {
        String role = roleInCourse(claims, course);
        return claims != null && (claims.isAdmin || "teacher".equals(role));
    }

    private String pickAuthorRole(Models.TokenClaims claims, String course) {
        if (claims == null) return "UNKNOWN";
        if (claims.isAdmin) return "ADMIN";

        String role = roleInCourse(claims, course);
        if (role == null || role.isBlank()) return "UNKNOWN";
        return role.toUpperCase();
    }

    private Models.TokenClaims requireClaims(Map<String, Object>authPayload) {
        Object tokObj = authPayload.get("token");
        String token = tokObj == null ? "" : String.valueOf(tokObj);
        if (token.isBlank()) return null;

        try {
            return validateSignedToken(token);
        } catch (Exception e) {
            return null;
        }
    }

     private Models.TokenClaims requireClaims(NetMessage req) {
        Object tokObj = req.payload.get("token");
        String token = tokObj == null ? "" : String.valueOf(tokObj);
        if (token.isBlank()) return null;

        try {
            return validateSignedToken(token);
        } catch (Exception e) {
            return null;
        }
    }

    private Models.TokenClaims validateSignedToken(String token) throws Exception {
        if (asPublicKey == null || token == null || token.isBlank()) {
            return null;
        }

        String[] parts = token.split("\\.", 2);
        if (parts.length != 2) {
            return null;
        }

        byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[0]);
        byte[] signature = Base64.getUrlDecoder().decode(parts[1]);
        if (!SecurityUtil.rsaVerifyPSS(payloadBytes, signature, asPublicKey)) {
            return null;
        }

        Map<String, Object> payload = mapper.readValue(payloadBytes, new TypeReference<Map<String, Object>>() {});
        long expiresAt = asLong(payload.get("expiresAt"));
        long nowSec = System.currentTimeMillis() / 1000L;
        if (expiresAt <= 0 || nowSec > expiresAt) {
            return null;
        }

        String username = str(payload.get("username"));
        String email = str(payload.get("email"));
        boolean isAdmin = asBool(payload.get("isAdmin"));
        long issuedAt = asLong(payload.get("issuedAt"));

        Map<String, String> courseRoles = new java.util.HashMap<>();
        Object rolesObj = payload.get("courseRoles");
        if (rolesObj instanceof Map<?, ?> rolesMap) {
            for (Map.Entry<?, ?> e : rolesMap.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    courseRoles.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
                }
            }
        }

        return new Models.TokenClaims(username, email, isAdmin, courseRoles, issuedAt, expiresAt);
    }

    private PublicKey loadASPublicKey(String path) throws Exception {
        byte[] keyBytes = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(path));
        java.security.spec.X509EncodedKeySpec spec =
                new java.security.spec.X509EncodedKeySpec(keyBytes);
        return java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private static long asLong(Object o) {
        if (o instanceof Number n) return n.longValue();
        try {
            return Long.parseLong(str(o));
        } catch (Exception e) {
            return -1L;
        }
    }

    private static boolean asBool(Object o) {
        if (o instanceof Boolean b) return b;
        return "true".equalsIgnoreCase(str(o));
    }

    private NetMessage route(NetMessage req) throws Exception {
        if (req == null || req.type == null) {
            return NetMessage.err(null, ErrorCodes.BAD_REQUEST, "Missing message type");
        }

        switch (req.type) {
            case MessageTypes.RS_HEARTBEAT: {
                NetMessage ok = NetMessage.ok(req.requestId);
                ok.payload.put("msg", "heartbeat_ack");
                return ok;
            }

            // case MessageTypes.KEY_EXCHANGE_REQ: return handleKeyExchange(req);

            case MessageTypes.RS_CLIENT_HELLO_REQ: return handleClientHello(req);
            case MessageTypes.RS_CLIENT_KEY_REQ: return handleClientKey(req);

            case MessageTypes.VERIFY_RS_REQ: return handleVerifyRS(req);

            case MessageTypes.RESOURCE_CREATE_REQ: {
                 if (sessionAESKey == null || isBlank(clientNonce) || isBlank(rsNonce)) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "secure session not established");
                 }   

                Map<String, Object> authPayload = decryptEncryptedPayload(req);
                String title= s(authPayload.get("fileName"));
                String course = s(authPayload.get("course"));
                String content = s(authPayload.get("fileData"));
                String tag=s(authPayload.get("tag"));
                String providedClientNonce=s(authPayload.get("clientNonce"));
                String providedRsNonce = s(authPayload.get("rsNonce"));
                Object timestampObj = authPayload.get("timestamp");
                Models.TokenClaims claims = requireClaims(authPayload);

                if (!Objects.equals(clientNonce, providedClientNonce) || !Objects.equals(rsNonce, providedRsNonce)) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "nonce validation failed");
                }

                long timestamp = ((Number) timestampObj).longValue();
                long now = System.currentTimeMillis();
                if (Math.abs(now - timestamp) > AUTH_TIMESTAMP_SKEW_MS) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "stale authentication request");
                }
                if (claims == null) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
                }
                if (course.isBlank()) {
                    return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing course");
                }
                if (!claims.isAdmin && !enrolledInCourse(claims, course)) {
                    return NetMessage.err(req.requestId, MessageTypes.ERROR_NOT_ENROLLED, "not enrolled in course");
                }

                if (title == null || title.isBlank() || content == null) {
                    return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing fileName/fileData");
                }
                if (!isValidTag(tag)) {
                    return NetMessage.err(req.requestId, MessageTypes.ERROR_BAD_TAG, "tag must be assignment/test/project");
                }

                String k = key(course, title);
                String authorRole = pickAuthorRole(claims, course);

                synchronized (state) {
                    if (state.posts.containsKey(k)) {
                        NetMessage err = NetMessage.err(req.requestId, MessageTypes.ERROR_DB_FILE_DUPLICATE, "duplicate title");
                        err.payload.put("error", MessageTypes.ERROR_DB_FILE_DUPLICATE);
                        return err;
                    }

                    state.posts.put(k, new StoredPost(course, title, content, tag, claims.username, authorRole));

                    try {
                        Persistence.saveAtomic(state, statePath);
                    } catch (Exception e) {
                        return NetMessage.err(req.requestId, "ERROR_PERSIST", "Failed to save state: " + e.getMessage());
                    }
                }

                NetMessage ok = NetMessage.ok(req.requestId);
                ok.payload.put("success", "success");
                ok.payload.put("course", course);
                ok.payload.put("tag", tag);
                ok.payload.put("author", claims.username);
                ok.payload.put("authorRole", authorRole);
                return ok;
            }
        
            case MessageTypes.RESOURCE_READ_REQ: {
                if (sessionAESKey == null || isBlank(clientNonce) || isBlank(rsNonce)) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "secure session not established");
                 }   

                 Map<String, Object> authPayload = decryptEncryptedPayload(req);
                String title= s(authPayload.get("fileName"));
                String course = s(authPayload.get("course"));
                String providedClientNonce=s(authPayload.get("clientNonce"));
                String providedRsNonce = s(authPayload.get("rsNonce"));
                Object timestampObj = authPayload.get("timestamp");
                Models.TokenClaims claims = requireClaims(authPayload);

                if (!Objects.equals(clientNonce, providedClientNonce) || !Objects.equals(rsNonce, providedRsNonce)) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "nonce validation failed");
                }

                long timestamp = ((Number) timestampObj).longValue();
                long now = System.currentTimeMillis();
                if (Math.abs(now - timestamp) > AUTH_TIMESTAMP_SKEW_MS) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "stale authentication request");
                }

                if (claims == null) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
                }

                if (course.isBlank()) {
                    return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing course");
                }
                if (!claims.isAdmin && !enrolledInCourse(claims, course)) {
                    return NetMessage.err(req.requestId, MessageTypes.ERROR_NOT_ENROLLED, "not enrolled in course");
                }

                if (title == null || title.isBlank()) {
                    return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing fileName");
                }

                StoredPost post;
                synchronized (state) {
                    post = state.posts.get(key(course, title));
                }

                if (post == null) {
                    NetMessage err = NetMessage.err(req.requestId, MessageTypes.ERROR_DB_FILE_NOT_EXIST, "not found");
                    err.payload.put("error", MessageTypes.ERROR_DB_FILE_NOT_EXIST);
                    return err;
                }
                
                Map<String, Object>rsPayload= new HashMap<>();

                rsPayload.put("course", post.course);
                rsPayload.put("fileName", post.title);
                rsPayload.put("tag", post.tag);
                rsPayload.put("author", post.author);
                rsPayload.put("authorRole", post.authorRole);
                rsPayload.put("content", post.content);
                rsPayload.put("clientNonce", clientNonce);
                rsPayload.put("rsNonce", rsNonce);
                rsPayload.put("timestamp", System.currentTimeMillis());

                byte[] plaintext = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(rsPayload);

                //encrypt with session aes key (GCM, random IV)
                byte[] iv = new byte[12];
                new java.security.SecureRandom().nextBytes(iv);
                byte[] ciphertext = SecurityUtil.aesGcmEncrypt(plaintext, sessionAESKey, iv);

                NetMessage ok = NetMessage.ok(req.requestId);
                ok.payload.put("aes_encrypted", Base64.getEncoder().encodeToString(ciphertext));
                ok.payload.put("iv", Base64.getEncoder().encodeToString(iv));
                ok.payload.put("clientNonce", clientNonce);
                ok.payload.put("rsNonce", rsNonce);
                ok.payload.put("timestamp", System.currentTimeMillis());
                return ok;
            }

            case MessageTypes.RESOURCE_UPDATE_REQ: {
                if (sessionAESKey == null || isBlank(clientNonce) || isBlank(rsNonce)) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "secure session not established");
                }   

                Models.TokenClaims claims = requireClaims(req);
                if (claims == null) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
                }

                String course = norm(String.valueOf(req.payload.get("course")));
                if (course.isBlank()) {
                    return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing course");
                }
                if (!claims.isAdmin && !enrolledInCourse(claims, course)) {
                    return NetMessage.err(req.requestId, MessageTypes.ERROR_NOT_ENROLLED, "not enrolled in course");
                }

                String tag = norm(String.valueOf(req.payload.get("tag")));
                if (!tag.isBlank() && !isValidTag(tag)) {
                    return NetMessage.err(req.requestId, MessageTypes.ERROR_BAD_TAG, "tag must be assignment/test/project");
                }

                List<String> out = new ArrayList<>();
                synchronized (state) {
                    for (Map.Entry<String, StoredPost> entry : state.posts.entrySet()) {
                        StoredPost p = entry.getValue();
                        if (p == null) continue;
                        if (!course.equalsIgnoreCase(p.course)) continue;
                        if (!tag.isBlank() && (p.tag == null || !tag.equalsIgnoreCase(p.tag))) continue;

                        out.add(p.title + " | tag=" + p.tag + " | author=" + p.author + " (" + p.authorRole + ")");
                    }
                }

                Map<String, Object>rsPayload= new HashMap<>();

                rsPayload.put("course", course);
                rsPayload.put("posts", out);
                rsPayload.put("clientNonce", clientNonce);
                rsPayload.put("rsNonce", rsNonce);
                rsPayload.put("timestamp", System.currentTimeMillis());

                byte[] plaintext = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(rsPayload);

                //encrypt with session aes key (GCM, random IV)
                byte[] iv = new byte[12];
                new java.security.SecureRandom().nextBytes(iv);
                byte[] ciphertext = SecurityUtil.aesGcmEncrypt(plaintext, sessionAESKey, iv);


                NetMessage ok = NetMessage.ok(req.requestId);
                ok.payload.put("aes_encrypted", Base64.getEncoder().encodeToString(ciphertext));
                ok.payload.put("iv", Base64.getEncoder().encodeToString(iv));
                ok.payload.put("clientNonce", clientNonce);
                ok.payload.put("rsNonce", rsNonce);
                ok.payload.put("timestamp", System.currentTimeMillis());
                return ok;
            }

            case MessageTypes.RESOURCE_DELETE_REQ: {
                Models.TokenClaims claims = requireClaims(req);
                if (claims == null) {
                    return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
                }

                String course = norm(String.valueOf(req.payload.get("course")));
                if (course.isBlank()) {
                    return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing course");
                }
                if (!claims.isAdmin && !enrolledInCourse(claims, course)) {
                    return NetMessage.err(req.requestId, MessageTypes.ERROR_NOT_ENROLLED, "not enrolled in course");
                }

                String title = String.valueOf(req.payload.get("fileName"));
                if (title == null || title.isBlank()) {
                    return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "missing fileName");
                }

                String k = key(course, title);

                synchronized (state) {
                    StoredPost post = state.posts.get(k);
                    if (post == null) {
                        NetMessage err = NetMessage.err(req.requestId, MessageTypes.ERROR_DB_FILE_NOT_EXIST, "not found");
                        err.payload.put("error", MessageTypes.ERROR_DB_FILE_NOT_EXIST);
                        return err;
                    }

                    if (!canDeletePost(claims, course)) {
                        return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, "only teacher/admin can delete posts");
                    }

                    state.posts.remove(k);

                    try {
                        Persistence.saveAtomic(state, statePath);
                    } catch (Exception e) {
                        return NetMessage.err(req.requestId, "ERROR_PERSIST", "Failed to save state: " + e.getMessage());
                    }
                }

                NetMessage ok = NetMessage.ok(req.requestId);
                ok.payload.put("success", "deleted");
                ok.payload.put("title", title);
                ok.payload.put("course", course);
                return ok;
            }

            default:
                return NetMessage.err(req.requestId, ErrorCodes.UNKNOWN_TYPE, "Unknown type: " + req.type);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4 && args.length != 6) {
            System.out.println("Usage: java main.rs.ResourceServer <listenPort> <statePath> <asHost> <asPort> [heartbeatHost heartbeatPort]");
            System.exit(1);
        }

        int listenPort = Integer.parseInt(args[0]);
        String statePath = args[1];

        String hbHost = null;
        int hbPort = -1;

        if (args.length == 6) {
            hbHost = args[4];
            hbPort = Integer.parseInt(args[5]);
        }

        new ResourceServer(listenPort, statePath, hbHost, hbPort).start();
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String s(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private Map<String, Object> decryptEncryptedPayload(NetMessage req) throws Exception {
        String encryptedB64 = s(req.payload.get("aes_encrypted"));
        String ivB64 = s(req.payload.get("iv"));
        if (isBlank(encryptedB64) || isBlank(ivB64)) {
            throw new IllegalArgumentException("missing encrypted payload");
        }

        byte[] ciphertext = java.util.Base64.getDecoder().decode(encryptedB64);
        byte[] iv = java.util.Base64.getDecoder().decode(ivB64);
        byte[] plaintext = SecurityUtil.aesGcmDecrypt(ciphertext, sessionAESKey, iv);
        return new com.fasterxml.jackson.databind.ObjectMapper()
            .readValue(plaintext, new TypeReference<Map<String, Object>>() {});
    }

    private NetMessage handleVerifyRS(NetMessage req) throws Exception {
        String hostname = s(req.payload.get("host"));
        Object port = req.payload.get("port");
        NetMessage resp=NetMessage.ok(req.requestId);
        resp.payload.put("rsId", id);
        resp.payload.put("publicKeyB64", this.publicKey);
        resp.payload.put("hostname",hostname);
        resp.payload.put("port", port);
        resp.payload.put("requestValidFrom", System.currentTimeMillis() );
        resp.payload.put("requestValidTo", Math.addExact(System.currentTimeMillis(), this.CERT_TIMESTAMP_SKEW_MS));

        return resp;
    }

    //key exchange
    private NetMessage handleKeyExchange(NetMessage req) throws Exception {
        //expects{ "rsa_encrypted": <byte[] as Base64 string> }
        String b64 = (String) req.payload.get("rsa_encrypted");
        if (b64 == null) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "Missing encrypted payload");
        }
        byte[] encrypted = java.util.Base64.getDecoder().decode(b64); 

        //decrypt with AS private key
        //expects AES key (32 bytes) || clientNonce (16 bytes)
        byte[] decrypted = SecurityUtil.rsaDecryptOAEP(encrypted, privateKey);
        byte[] aesKeyBytes = java.util.Arrays.copyOfRange(decrypted, 0, 32);
        byte[] nonceBytes = java.util.Arrays.copyOfRange(decrypted, 32, decrypted.length);
        this.sessionAESKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
        this.clientNonce = new String(nonceBytes, java.nio.charset.StandardCharsets.UTF_8);


        //generate as nonce
        this.rsNonce = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);

        //{ "as_nonce": <string>, "status": "ok" }
        java.util.Map<String, Object> respPayload = new java.util.HashMap<>();
        respPayload.put("rs_nonce", rsNonce);
        respPayload.put("status", "ok");

        //encrypt AES key (GCM, random IV)
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        //json format
        byte[] plaintext = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(respPayload);
        byte[] ciphertext = SecurityUtil.aesGcmEncrypt(plaintext, sessionAESKey, iv);

        //sends{ "aes_encrypted": <Base64>, "iv": <Base64> }
        NetMessage resp = NetMessage.ok(req.requestId);
        resp.type = MessageTypes.KEY_EXCHANGE_RESP;
        resp.payload.put("aes_encrypted", java.util.Base64.getEncoder().encodeToString(ciphertext));
        resp.payload.put("iv", java.util.Base64.getEncoder().encodeToString(iv));
        return resp;
    }

}