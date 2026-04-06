package main.client;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import main.common.MessageTypes;
import main.common.Models;
import main.common.NetMessage;
import java.util.*;
import main.common.SecurityUtil;
import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import main.common.SecureEnvelope;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import java.io.Closeable;

   

public class ClientCLI {

    private static final TypeReference<Map<String, Object>> MAP_STRING_OBJECT_TYPE =
            new TypeReference<Map<String, Object>>() {};

    private final String asHost;
    private final int asPort;
    private final String rsHost;
    private final int rsPort;

    private String username;
    private String token;

    private boolean isAdmin = false;
    private Map<String, String> courseRoles = new HashMap<>();
    private String currentCourse;

    private SecretKey sessionAsAESKey = null;
    private String clientNonce = null;
    private String asNonce = null;
    private PublicKey asPublicKey = null;

    private PublicKey rsPublicKey=null;
    private SecretKey sessionRsAESKey=null;
    private String rsClientNonce=null;
    private String rsNonce=null;

    private Socket asSocket = null;
    private ObjectOutputStream asOut = null;
    private ObjectInputStream asIn = null;

    private Socket rsSocket=null;
    private ObjectOutputStream rsOut=null;
    private ObjectInputStream rsIn=null;

    private final ObjectMapper mapper = new ObjectMapper();

    public ClientCLI(String asHost, int asPort, String rsHost, int rsPort) {
        this.asHost = asHost;
        this.asPort = asPort;
        this.rsHost = rsHost;
        this.rsPort = rsPort;
    }

    private void connectToAS() throws Exception {
        if (asSocket != null && !asSocket.isClosed()) return;

        asSocket = new Socket(asHost, asPort);
        asOut = new ObjectOutputStream(asSocket.getOutputStream());
        asIn = new ObjectInputStream(asSocket.getInputStream());
    }

    private void closeASConnection() {
        closeQuietly(asIn);
        closeQuietly(asOut);
        closeQuietly(asSocket);
        asIn = null;
        asOut = null;
        asSocket = null;
    }

    private void closeRSConnection() {
        closeQuietly(rsIn);
        closeQuietly(rsOut);
        closeQuietly(rsSocket);
        rsIn = null;
        rsOut = null;
        rsSocket = null;
    }

    private void closeQuietly(Object o) {
        try {
            if (o instanceof Closeable c) c.close();
            else if (o instanceof Socket s) s.close();
        } catch (Exception ignored) {}
    }

    private NetMessage sendPlainToAS(NetMessage req) throws Exception {
        connectToAS();
        asOut.writeObject(req);
        asOut.flush();
        return (NetMessage) asIn.readObject();
    }

    private NetMessage sendSecureToAS(NetMessage req) throws Exception {
        if (sessionAsAESKey == null) {
            if (asPublicKey == null) {
                throw new IllegalStateException("secure AS session not established");
            }
            performASKeyExchange(asPublicKey);
        }

        connectToAS();

        byte[] plaintext = mapper.writeValueAsBytes(req);
        byte[] iv = SecurityUtil.randomBytes(12);
        byte[] ciphertext = SecurityUtil.aesGcmEncrypt(plaintext, sessionAsAESKey, iv);

        SecureEnvelope env = new SecureEnvelope(iv, ciphertext);
        asOut.writeObject(env);
        asOut.flush();

        Object respObj = asIn.readObject();
        if (!(respObj instanceof SecureEnvelope respEnv)) {
            throw new IllegalStateException("expected secure response from AS");
        }

        byte[] respPlain = SecurityUtil.aesGcmDecrypt(respEnv.ciphertext, sessionAsAESKey, respEnv.iv);
        return mapper.readValue(respPlain, NetMessage.class);
    }

    //load the as public key from a Base64-encoded file
    public static PublicKey loadASPublicKey(String filename) throws Exception {
        byte[] keyBytes = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(filename));
        java.security.spec.X509EncodedKeySpec spec =
                new java.security.spec.X509EncodedKeySpec(keyBytes);
        return java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static PublicKey loadRSPublicKey(String filename) throws Exception {
        byte[] keyBytes = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public void performASKeyExchange(PublicKey asPublicKey) throws Exception {
        this.asPublicKey = asPublicKey;
        //gen aes key and c nonce
        sessionAsAESKey = SecurityUtil.generateAESKey();
        byte[] aesKeyBytes = sessionAsAESKey.getEncoded();
        clientNonce = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        byte[] nonceBytes = clientNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        //cat aes key and nonce
        byte[] combined = new byte[aesKeyBytes.length + nonceBytes.length];
        System.arraycopy(aesKeyBytes, 0, combined, 0, aesKeyBytes.length);
        System.arraycopy(nonceBytes, 0, combined, aesKeyBytes.length, nonceBytes.length);

        //encrypt with as public key (OAEP)
        byte[] encrypted = SecurityUtil.rsaEncryptOAEP(combined, asPublicKey);
        String b64 = Base64.getEncoder().encodeToString(encrypted);

        //send KEY_EXCHANGE_REQ
        NetMessage req = NetMessage.request(MessageTypes.KEY_EXCHANGE_REQ);
        req.payload.put("rsa_encrypted", b64);
        NetMessage resp = sendPlainToAS(req);
        if (!MessageTypes.KEY_EXCHANGE_RESP.equals(resp.type)) {
            throw new RuntimeException("Key exchange failed: bad response type");
        }

        //decrypt response with aes key
        String aesEncryptedB64 = (String) resp.payload.get("aes_encrypted");
        String ivB64 = (String) resp.payload.get("iv");
        byte[] ciphertext = Base64.getDecoder().decode(aesEncryptedB64);
        byte[] iv = Base64.getDecoder().decode(ivB64);
        byte[] plaintext = SecurityUtil.aesGcmDecrypt(ciphertext, sessionAsAESKey, iv);

        //json
        java.util.Map<String, Object> respPayload = new com.fasterxml.jackson.databind.ObjectMapper()
            .readValue(plaintext, MAP_STRING_OBJECT_TYPE);
        asNonce = (String) respPayload.get("as_nonce");
        String status = (String) respPayload.get("status");
        if (!"ok".equals(status)) {
            throw new RuntimeException("Key exchange failed: status not ok");
        }
        System.out.println("Key exchange complete. Client nonce: " + clientNonce + ", AS nonce: " + asNonce);
    }

    private void connectToRS() throws Exception{
        if(rsSocket!=null && !rsSocket.isClosed()) return;

        rsSocket=new Socket(rsHost, rsPort);
        rsOut=new ObjectOutputStream(rsSocket.getOutputStream());
        rsIn=new ObjectInputStream(rsSocket.getInputStream());
    }

    private NetMessage sendPlainToRS (NetMessage req) throws Exception {
        connectToRS();
        rsOut.writeObject(req);
        rsOut.flush();
        return (NetMessage)rsIn. readObject();
    }

    private NetMessage sendSecureToRS(NetMessage req) throws Exception {
        if (sessionRsAESKey == null) {
            throw new IllegalStateException("secure RS session not established");
        }

        connectToRS();

        byte[] plaintext = mapper.writeValueAsBytes(req);
        byte[] iv = SecurityUtil.randomBytes(12);
        byte[] ciphertext = SecurityUtil.aesGcmEncrypt(plaintext, sessionRsAESKey, iv);

        SecureEnvelope env = new SecureEnvelope(iv, ciphertext);
        rsOut.writeObject(env);
        rsOut.flush();

        Object respObj = rsIn.readObject();
        if (!(respObj instanceof SecureEnvelope respEnv)) {
            throw new IllegalStateException("expected secure response from RS");
        }

        byte[] respPlain = SecurityUtil.aesGcmDecrypt(respEnv.ciphertext, sessionRsAESKey, respEnv.iv);
        return mapper.readValue(respPlain, NetMessage.class);
    }

    public void verifyRSPossessionHandshake(PublicKey rsPublicKey) throws Exception {
        this.rsPublicKey = rsPublicKey;
        connectToRS();

        String version = "1.0";
        List<String> supportedAlgorithms = List.of("RSA", "SHA256");
        String nc = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);

        java.security.KeyPair eph = SecurityUtil.generateRSAKeyPair();
        String clientEphemeralPublicKeyB64 = Base64.getEncoder().encodeToString(eph.getPublic().getEncoded());

        this.rsClientNonce = nc;

        // send client hello
        NetMessage req = NetMessage.request(MessageTypes.RS_CLIENT_HELLO_REQ);
        req.payload.put("version", version);
        req.payload.put("supportedAlgorithms", supportedAlgorithms);
        req.payload.put("Nc", nc);
        req.payload.put("clientEphemeralPublicKey", clientEphemeralPublicKeyB64);

        NetMessage resp = sendPlainToRS(req);
        if (!MessageTypes.RS_SERVER_HELLO_RESP.equals(resp.type)) {
            throw new IllegalStateException("unexpected response type: " + resp.type);
        }

        // ServerHello
        String selectedVersion = s(resp.payload.get("version"));
        String ns = s(resp.payload.get("Ns"));
        String serverEphemeralPublicKeyB64 = s(resp.payload.get("serverEphemeralPublicKey"));
        String serverSignatureB64 = s(resp.payload.get("serverSignature"));
        String rsId = s(resp.payload.get("RS_ID"));

        Object algObj = resp.payload.get("selectedAlgorithms");
        List<String> selectedAlgorithms = new ArrayList<>();
        if (algObj instanceof List<?>) {
            for (Object x : (List<?>) algObj) {
                selectedAlgorithms.add(String.valueOf(x));
            }
        }

        this.rsNonce = ns;

        // verify ServerHello
        verifyServerHelloSignature(
                rsPublicKey,
                rsId,
                version,
                supportedAlgorithms,
                nc,
                clientEphemeralPublicKeyB64,
                selectedVersion,
                selectedAlgorithms,
                ns,
                serverEphemeralPublicKeyB64,
                serverSignatureB64
        );

        System.out.println("RS possession handshake verified. Nc=" + nc + ", Ns=" + ns);

            // savw transcript
        this.rsHandshakeTranscript = buildHandshakeTranscript(
                rsId,
                version,
                supportedAlgorithms,
                nc,
                clientEphemeralPublicKeyB64,
                selectedVersion,
                selectedAlgorithms,
                ns,
                serverEphemeralPublicKeyB64
        );

        //create premaster key
        this.rsPreMasterKey = SecurityUtil.generateAESKey();

        byte[] encryptedPreMaster = SecurityUtil.rsaEncryptOAEP(
                rsPreMasterKey.getEncoded(),
                rsPublicKey
        );

        this.rsSessionKey = deriveSessionKey(rsPreMasterKey, nc, ns);

        //client Finished
        String clientFinished = computeFinished(
                "client finished",
                rsSessionKey,
                rsHandshakeTranscript
        );

        //send to RS
        NetMessage keyReq = NetMessage.request(MessageTypes.RS_CLIENT_KEY_REQ);
        keyReq.payload.put("encryptedPreMaster", Base64.getEncoder().encodeToString(encryptedPreMaster));
        keyReq.payload.put("clientFinished", clientFinished);

        NetMessage finishedResp = sendPlainToRS(keyReq);
        if (!MessageTypes.RS_FINISHED_RESP.equals(finishedResp.type)) {
            throw new IllegalStateException("unexpected finished response type: " + finishedResp.type);
        }

        String serverFinished = s(finishedResp.payload.get("serverFinished"));
        String expectedServerFinished = computeFinished(
                "server finished",
                rsSessionKey,
                rsHandshakeTranscript
        );

        if (!Objects.equals(serverFinished, expectedServerFinished)) {
            throw new IllegalStateException("server Finished verification failed");
        }

        this.sessionRsAESKey = this.rsSessionKey;

        System.out.println("Full RS handshake complete. Session key established.");
    }

    public void verifyServerHelloSignature(
            PublicKey trustedRsPublicKey,
            String rsId,
            String clientVersion,
            List<String> supportedAlgorithms,
            String nc,
            String clientEphemeralPublicKeyB64,
            String serverVersion,
            List<String> selectedAlgorithms,
            String ns,
            String serverEphemeralPublicKeyB64,
            String serverSignatureB64
    ) throws Exception {

        if (trustedRsPublicKey == null) {
            throw new IllegalArgumentException("trusted RS public key is null");
        }

        if (!Objects.equals(clientVersion, serverVersion)) {
            throw new IllegalStateException("protocol version mismatch");
        }

        if (ns == null || ns.isBlank()) {
            throw new IllegalStateException("missing server nonce");
        }

        if (serverEphemeralPublicKeyB64 == null || serverEphemeralPublicKeyB64.isBlank()) {
            throw new IllegalStateException("missing server ephemeral public key");
        }

        if (serverSignatureB64 == null || serverSignatureB64.isBlank()) {
            throw new IllegalStateException("missing server signature");
        }

        for (String alg : selectedAlgorithms) {
            if (!supportedAlgorithms.contains(alg)) {
                throw new IllegalStateException("server selected unsupported algorithm: " + alg);
            }
        }

        String payload = buildServerHelloSigningPayload(
                rsId,
                clientVersion,
                supportedAlgorithms,
                nc,
                clientEphemeralPublicKeyB64,
                serverVersion,
                selectedAlgorithms,
                ns,
                serverEphemeralPublicKeyB64
        );

        String payloadHashHex = SecurityUtil.sha256(payload);
        byte[] toVerify = payloadHashHex.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] sig = Base64.getDecoder().decode(serverSignatureB64);

        boolean ok = SecurityUtil.rsaVerifyPSS(toVerify, sig, trustedRsPublicKey);
        if (!ok) {
            throw new IllegalStateException("server signature verification failed");
        }
    }

    public String buildServerHelloSigningPayload(//public for test
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

    private SecretKey rsSessionKey = null;
    private SecretKey rsPreMasterKey = null;
    private byte[] rsHandshakeTranscript = null;

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

    //public for test
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

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Usage: java main.client.ClientCLI <asHost> <asPort> <rsHost> <rsPort>");
            System.exit(1);
        }
        ClientCLI cli = new ClientCLI(args[0], Integer.parseInt(args[1]), args[2], Integer.parseInt(args[3]));
        //as pk and do key exchange
        try {
            PublicKey asPublicKey = loadASPublicKey("data/keys/as_public.key");
            cli.performASKeyExchange(asPublicKey);
        } catch (Exception e) {
            System.err.println("Failed to load AS public key or perform key exchange: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        //rs public key is pre-trusted from local file
        try {
            PublicKey rsPublicKey = loadRSPublicKey("data/keys/rs_public.key");
            cli.verifyRSPossessionHandshake(rsPublicKey);
        } catch (Exception e) {
            System.err.println("Failed to load RS public key or perform key exchange: " + e.getMessage());
            e.printStackTrace();
            return;
        }
        cli.run();
    }

    private void run() throws Exception {
        Scanner sc = new Scanner(System.in);

        while (true) {
            System.out.println("Login to begin.");
            if (login(sc)) {
                break;
            }
        }

        select(sc);

        while (true) {
            System.out.print("> ");
            String line = sc.nextLine().trim();
            if (line.isEmpty()) continue;

            String[] p = line.split("\\s+", 2);
            String cmd = p[0].toLowerCase();
            String arg = p.length > 1 ? p[1].trim() : "";

            try {
                switch (cmd) {
                    case "help" -> help();
                    case "courses" -> printCourses();
                    case "whoami" -> whoami();
                    case "select" -> select(sc);
                    case "logout" -> {
                        logout();
                        while (true) {
                            System.out.println("Login to begin.");
                            if (login(sc)) break;
                        }
                        select(sc);
                    }

                    case "add" -> {
                        if (line.toLowerCase().startsWith("add course")) {
                            addCourse(sc);
                        } else {
                            System.out.println("Unknown command");
                        }
                    }

                    case "delete" -> {
                        String lower = line.toLowerCase();
                        if (lower.startsWith("delete course")) {
                            String rest = line.length() > "delete course".length()
                                    ? line.substring("delete course".length()).trim()
                                    : "";
                            deleteCourse(rest, sc);
                        } else if (lower.startsWith("delete user")) {
                            String rest = line.length() > "delete user".length()
                                    ? line.substring("delete user".length()).trim()
                                    : "";
                            deleteUser(rest);
                        } else {
                            deletePost(arg);
                        }
                    }

                    case "create" -> {
                        if (line.equalsIgnoreCase("create user")) {
                            createUser(sc);
                        } else {
                            System.out.println("Unknown command");
                        }
                    }

                    case "users" -> listUsers();
                    case "roster" -> roster();
                    case "enroll" -> enroll(sc);
                    case "kick" -> kick(sc);
                    case "drop" -> dropSelf(arg, sc);

                    case "post" -> post(sc);
                    case "list" -> list("");
                    case "listtag" -> list(arg);
                    case "view" -> view(arg);

                    case "exit" -> {
                        return;
                    }

                    default -> System.out.println("Unknown command");
                }
            } catch (Exception e) {
                System.out.println("ERROR: " + e.getMessage());
            }
        }
    }

    private boolean login(Scanner sc) throws Exception {
        System.out.print("username: ");
        String inputUser = sc.nextLine().trim().toLowerCase();

        System.out.print("password: ");
        String pw = sc.nextLine().trim();

        if (sessionAsAESKey == null) {
            if (asPublicKey == null) {
                throw new IllegalStateException("cannot perform login: AS public key unavailable");
            }
            performASKeyExchange(asPublicKey);
        }

        Map<String, Object> authPayload = new HashMap<>();
        authPayload.put("username", inputUser);
        authPayload.put("password", pw);
        authPayload.put("clientNonce", clientNonce);
        authPayload.put("asNonce", asNonce);
        authPayload.put("timestamp", System.currentTimeMillis());

        byte[] plaintext = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(authPayload);

        //encrypt with session aes key (GCM, random IV)
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        byte[] ciphertext = SecurityUtil.aesGcmEncrypt(plaintext, sessionAsAESKey, iv);

        //send encrypted login request
        NetMessage req = NetMessage.request(MessageTypes.LOGIN_REQ);
        req.payload.put("aes_encrypted", Base64.getEncoder().encodeToString(ciphertext));
        req.payload.put("iv", Base64.getEncoder().encodeToString(iv));
        req.payload.put("clientNonce", clientNonce);
        req.payload.put("asNonce", asNonce);
        req.payload.put("timestamp", System.currentTimeMillis());

        NetMessage resp = sendSecureToAS(req);
        if (!printResp(resp, req.type)) {
            return false;
        }

        this.username = inputUser;
        return true;
    }

    private void select(Scanner sc) throws Exception {
        NetMessage req = NetMessage.request(MessageTypes.TOKEN_ISSUE_REQ);
        req.payload.put("username", username);

        NetMessage resp = sendSecureToAS(req);
        if (!printResp(resp, req.type)) {
            token = null;
            isAdmin = false;
            courseRoles = new HashMap<>();
            currentCourse = null;
            throw new IllegalStateException("could not start session");
        }

        Object respClientNonce = resp.payload.get("clientNonce");
        Object respAsNonce = resp.payload.get("asNonce");
        Object expiresObj = resp.payload.get("expiresAt");
        if (!Objects.equals(clientNonce, String.valueOf(respClientNonce))
                || !Objects.equals(asNonce, String.valueOf(respAsNonce))
                || !(expiresObj instanceof Number)) {
            throw new IllegalStateException("invalid token response metadata");
        }

        Object tokenObj = resp.payload.get("token");
        if (!(tokenObj instanceof String)) {
            token = null;
            isAdmin = false;
            courseRoles = new HashMap<>();
            currentCourse = null;
            throw new IllegalStateException("server returned invalid session data");
        }

        token = (String) tokenObj;
        Models.TokenClaims claims = validateSignedToken(token);
        if (claims == null) {
            token = null;
            isAdmin = false;
            courseRoles = new HashMap<>();
            currentCourse = null;
            throw new IllegalStateException("token signature/expiration validation failed");
        }

        isAdmin = claims.isAdmin;
        courseRoles = claims.courseRoles == null ? new HashMap<>() : new HashMap<>(claims.courseRoles);

        NetMessage listReq = NetMessage.request(MessageTypes.COURSE_LIST_REQ);
        listReq.payload.put("token", token);
        NetMessage listResp = sendSecureToAS(listReq);
        if (!printResp(listResp, listReq.type)) {
            currentCourse = null;
            return;
        }

        Object adminObj = listResp.payload.get("isAdmin");
        boolean adminView = adminObj instanceof Boolean && (Boolean) adminObj;
        Object coursesObj = listResp.payload.get("courses");

        List<String> availableCourses = new java.util.ArrayList<>();
        if (coursesObj instanceof List<?>) {
            for (Object c : (List<?>) coursesObj) {
                if (c != null) availableCourses.add(String.valueOf(c).trim().toLowerCase());
            }
        }

        if (adminView) {
            System.out.println("All courses:");
        } else {
            System.out.println("Courses:");
        }

        if (availableCourses.isEmpty()) {
            System.out.println(" (none)");
            currentCourse = null;
            System.out.println("No active course selected.");
            return;
        }

        for (String c : availableCourses) {
            if (adminView) {
                System.out.println(" - " + c);
            } else {
                String role = courseRoles.get(c);
                if (role == null || role.isBlank()) {
                    System.out.println(" - " + c);
                } else {
                    System.out.println(" - " + c + " (" + role + ")");
                }
            }
        }

        while (true) {
            System.out.print("Pick course (or press enter for none): ");
            String pick = sc.nextLine().trim().toLowerCase();

            if (pick.isBlank()) {
                currentCourse = null;
                System.out.println("No active course selected.");
                return;
            }

            if (availableCourses.contains(pick)) {
                currentCourse = pick;
                System.out.println("Active course: " + currentCourse);
                return;
            }

            System.out.println("Not a valid course.");
        }
    }

    private void enroll(Scanner sc) throws Exception {
        needToken();
        needCourse();

        if (!isAdmin && !isTeacher(currentCourse)) {
            System.out.println("Not allowed.");
            return;
        }

        System.out.print("username: ");
        String user = sc.nextLine().trim().toLowerCase();

        System.out.print("role (student/ta");
        if (isAdmin) System.out.print("/teacher");
        System.out.println("): ");
        String role = sc.nextLine().trim().toLowerCase();

        NetMessage req = NetMessage.request(MessageTypes.COURSE_ENROLL_REQ);
        req.payload.put("token", token);
        req.payload.put("username", user);
        req.payload.put("course", currentCourse);
        req.payload.put("role", role);

        if (printResp(sendSecureToAS(req), req.type)) {
            refreshSession(sc);
        }
    }

    private void kick(Scanner sc) throws Exception {
        needToken();
        needCourse();

        if (!isAdmin && !isTeacher(currentCourse)) {
            System.out.println("Not allowed.");
            return;
        }

        System.out.print("username: ");
        String user = sc.nextLine().trim().toLowerCase();

        NetMessage req = NetMessage.request(MessageTypes.COURSE_UNENROLL_REQ);
        req.payload.put("token", token);
        req.payload.put("course", currentCourse);
        req.payload.put("student", user);

        if (printResp(sendSecureToAS(req), req.type)) {
            refreshSession(sc);
        }
    }

    private void dropSelf(String courseArg, Scanner sc) throws Exception {
        needToken();

        String course = (courseArg == null || courseArg.isBlank()) ? currentCourse : courseArg.trim().toLowerCase();
        if (course == null || course.isBlank()) {
            System.out.println("usage: drop <course>");
            return;
        }

        NetMessage req = NetMessage.request(MessageTypes.COURSE_DROP_REQ);
        req.payload.put("token", token);
        req.payload.put("course", course);

        if (printResp(sendSecureToAS(req), req.type)) {
            refreshSession(sc);
            if (course.equalsIgnoreCase(currentCourse)) {
                currentCourse = null;
            }
        }
    }

    private boolean isTeacher(String course) {
        return course != null && "teacher".equals(courseRoles.get(course));
    }

    private void printCourses() throws Exception {
        needToken();
        NetMessage req = NetMessage.request(MessageTypes.COURSE_LIST_REQ);
        req.payload.put("token", token);
        NetMessage resp = sendSecureToAS(req);
        if (!printResp(resp, req.type)) {
            return;
        }

        Object adminObj = resp.payload.get("isAdmin");
        boolean adminView = adminObj instanceof Boolean && (Boolean) adminObj;
        Object coursesObj = resp.payload.get("courses");
        Object rolesObj = resp.payload.get("courseRoles");

        if (adminView) {
            System.out.println("All courses:");
            if (coursesObj instanceof List<?>) {
                List<?> courses = (List<?>) coursesObj;
                if (courses.isEmpty()) {
                    System.out.println(" (none)");
                } else {
                    for (Object c : courses) {
                        System.out.println(" - " + c);
                    }
                }
            } else {
                System.out.println(" (none)");
            }
            return;
        }

        System.out.println("Courses:");
        if (rolesObj instanceof Map<?, ?> roleMap && !roleMap.isEmpty()) {
            for (Map.Entry<?, ?> e : roleMap.entrySet()) {
                System.out.println(" - " + e.getKey() + " (" + e.getValue() + ")");
            }
        } else {
            System.out.println(" (none)");
        }
    }

    private void whoami() {
        System.out.println("user=" + username);
        System.out.println("admin=" + isAdmin);
        System.out.println("courseRoles=" + courseRoles);
        System.out.println("active=" + (currentCourse == null ? "(none)" : currentCourse));
    }

    private void addCourse(Scanner sc) throws Exception {
        needToken();
        if (!isAdmin) {
            System.out.println("Admin only.");
            return;
        }

        System.out.print("code: ");
        String code = sc.nextLine().trim().toLowerCase();

        System.out.print("name: ");
        String name = sc.nextLine().trim();

        NetMessage req = NetMessage.request(MessageTypes.COURSE_ADD_REQ);
        req.payload.put("token", token);
        req.payload.put("course", code);
        req.payload.put("name", name);

        NetMessage resp = sendSecureToAS(req);
        printResp(resp, req.type);
    }

    private void deleteCourse(String c, Scanner sc) throws Exception {
        needToken();
        if (!isAdmin) {
            System.out.println("Admin only.");
            return;
        }

        if (c == null || c.isBlank()) {
            System.out.println("usage: delete course <course>");
            return;
        }

        NetMessage req = NetMessage.request(MessageTypes.COURSE_DEL_REQ);
        req.payload.put("token", token);
        req.payload.put("course", c.trim().toLowerCase());

        if (printResp(sendSecureToAS(req), req.type)) {
            refreshSession(sc);
        }
    }

    private void createUser(Scanner sc) throws Exception {
        needToken();
        if (!isAdmin) {
            System.out.println("Admin only.");
            return;
        }

        System.out.print("username: ");
        String u = sc.nextLine().trim().toLowerCase();

        System.out.print("password: ");
        String p = sc.nextLine().trim();

        System.out.print("email: ");
        String email = sc.nextLine().trim();

        NetMessage req = NetMessage.request(MessageTypes.ADMIN_CREATE_USER_REQ);
        req.payload.put("token", token);
        req.payload.put("username", u);
        req.payload.put("password", p);
        req.payload.put("email", email);

        printResp(sendSecureToAS(req), req.type);
    }

    private void deleteUser(String u) throws Exception {
        needToken();
        if (!isAdmin) {
            System.out.println("Admin only.");
            return;
        }

        if (u == null || u.isBlank()) {
            System.out.println("usage: delete user <username>");
            return;
        }

        NetMessage req = NetMessage.request(MessageTypes.ADMIN_DELETE_USER_REQ);
        req.payload.put("token", token);
        req.payload.put("username", u.trim().toLowerCase());

        printResp(sendSecureToAS(req), req.type);
    }

    private void listUsers() throws Exception {
        needToken();
        if (!isAdmin) {
            System.out.println("Admin only.");
            return;
        }

        NetMessage req = NetMessage.request(MessageTypes.ADMIN_LIST_USERS_REQ);
        req.payload.put("token", token);

        printResp(sendSecureToAS(req), req.type);
    }

    private void roster() throws Exception {
        needToken();
        needCourse();

        if (!isAdmin && !isTeacher(currentCourse)) {
            System.out.println("Admin or teacher only.");
            return;
        }

        NetMessage req = NetMessage.request(MessageTypes.COURSE_ROSTER_REQ);
        req.payload.put("token", token);
        req.payload.put("course", currentCourse);

        NetMessage resp = sendSecureToAS(req);
        printResp(resp, req.type);
    }

    private boolean post(Scanner sc) throws Exception {
        needToken();
        needCourse();

        if (sessionRsAESKey == null) {
            if (rsPublicKey == null) {
                throw new IllegalStateException("cannot post: RS public key unavailable");
            }
            verifyRSPossessionHandshake(rsPublicKey);
        }

        System.out.print("title: ");
        String title = sc.nextLine().trim();

        System.out.print("tag (assignment/test/project): ");
        String tag = sc.nextLine().trim().toLowerCase();

        System.out.print("content: ");
        String content = sc.nextLine();

        Map<String, Object>rsPayload= new HashMap<>();

        rsPayload.put("token", token);
        rsPayload.put("course", currentCourse);
        rsPayload.put("fileName", title);
        rsPayload.put("fileData", content);
        rsPayload.put("tag", tag);
        rsPayload.put("clientNonce", rsClientNonce);
        rsPayload.put("rsNonce", rsNonce);
        rsPayload.put("timestamp", System.currentTimeMillis());

        byte[] plaintext = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(rsPayload);

        //encrypt the RS-specific payload into the NetMessage fields
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        byte[] ciphertext = SecurityUtil.aesGcmEncrypt(plaintext, sessionRsAESKey, iv);

        NetMessage req = NetMessage.request(MessageTypes.RESOURCE_CREATE_REQ);
        req.payload.put("aes_encrypted", Base64.getEncoder().encodeToString(ciphertext));
        req.payload.put("iv", Base64.getEncoder().encodeToString(iv));
        req.payload.put("clientNonce", rsClientNonce);
        req.payload.put("rsNonce", rsNonce);
        req.payload.put("timestamp", System.currentTimeMillis());
        NetMessage resp = sendSecureToRS(req);
        if (!printResp(resp, req.type)) {
            return false;
        }
        return true;
    }

    private void list(String tag) throws Exception {
        needToken();
        needCourse();

        if (sessionRsAESKey == null) {
            if (rsPublicKey == null) {
                throw new IllegalStateException("cannot list: RS public key unavailable");
            }
            verifyRSPossessionHandshake(rsPublicKey);
        }

        NetMessage req = NetMessage.request(MessageTypes.RESOURCE_UPDATE_REQ);
        req.payload.put("token", token);
        req.payload.put("course", currentCourse);
        req.payload.put("tag", tag == null ? "" : tag);

        printResp(sendSecureToRS(req), req.type); 
    }

    private boolean view(String title) throws Exception {
        needToken();
        needCourse();

        if (title == null || title.isBlank()) {
            System.out.println("usage: view <title>");
            return false;
        }

        if (sessionRsAESKey == null) {
            if (rsPublicKey == null) {
                throw new IllegalStateException("cannot view: RS public key unavailable");
            }
            verifyRSPossessionHandshake(rsPublicKey);
        }
        
        Map<String, Object>rsPayload= new HashMap<>();

        rsPayload.put("token", token);
        rsPayload.put("course", currentCourse);
        rsPayload.put("fileName", title);
        rsPayload.put("clientNonce", rsClientNonce);
        rsPayload.put("rsNonce", rsNonce);
        rsPayload.put("timestamp", System.currentTimeMillis());

        byte[] plaintext = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(rsPayload);

        //encrypt the RS-specific payload into the NetMessage fields
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        byte[] ciphertext = SecurityUtil.aesGcmEncrypt(plaintext, sessionRsAESKey, iv);

        NetMessage req = NetMessage.request(MessageTypes.RESOURCE_READ_REQ);
        req.payload.put("aes_encrypted", Base64.getEncoder().encodeToString(ciphertext));
        req.payload.put("iv", Base64.getEncoder().encodeToString(iv));
        req.payload.put("clientNonce", rsClientNonce);
        req.payload.put("rsNonce", rsNonce);
        req.payload.put("timestamp", System.currentTimeMillis());

        NetMessage resp = sendSecureToRS(req);
        if (!printResp(resp, req.type)) {
            return false;
        }
        return true;
    }

    private void deletePost(String title) throws Exception {
        needToken();
        needCourse();

        if (title == null || title.isBlank()) {
            System.out.println("usage: delete <title>");
            return;
        }

        if (sessionRsAESKey == null) {
            if (rsPublicKey == null) {
                throw new IllegalStateException("cannot delete: RS public key unavailable");
            }
            verifyRSPossessionHandshake(rsPublicKey);
        }

        NetMessage req = NetMessage.request(MessageTypes.RESOURCE_DELETE_REQ);
        req.payload.put("token", token);
        req.payload.put("course", currentCourse);
        req.payload.put("fileName", title);

        printResp(sendSecureToRS(req), req.type);
    }

    private void refreshSession(Scanner sc) throws Exception {
        String oldCourse = currentCourse;

        NetMessage req = NetMessage.request(MessageTypes.TOKEN_ISSUE_REQ);
        req.payload.put("username", username);

        NetMessage resp = sendSecureToAS(req);
        if (!"OK".equals(resp.status)) return;

        Object tokenObj = resp.payload.get("token");
        Object claimsObj = resp.payload.get("claims");
        if (!(tokenObj instanceof String) || !(claimsObj instanceof Models.TokenClaims)) return;

        token = (String) tokenObj;
        Models.TokenClaims claims = (Models.TokenClaims) claimsObj;
        isAdmin = claims.isAdmin;
        courseRoles = claims.courseRoles == null ? new HashMap<>() : new HashMap<>(claims.courseRoles);

        NetMessage listReq = NetMessage.request(MessageTypes.COURSE_LIST_REQ);
        listReq.payload.put("token", token);
        NetMessage listResp = sendSecureToAS(listReq);
        if (!"OK".equals(listResp.status)) {
            currentCourse = null;
            return;
        }

        Object coursesObj = listResp.payload.get("courses");
        java.util.Set<String> availableCourses = new java.util.HashSet<>();
        if (coursesObj instanceof List<?>) {
            for (Object c : (List<?>) coursesObj) {
                if (c != null) availableCourses.add(String.valueOf(c).trim().toLowerCase());
            }
        }

        if (oldCourse != null && availableCourses.contains(oldCourse)) {
            currentCourse = oldCourse;
            return;
        }

        currentCourse = null;

        if (!availableCourses.isEmpty()) {
            System.out.println("Available courses changed.");
            System.out.println("Use reselect to choose an active course.");
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
    
    private Map<String, Object> decryptRsEncryptedPayload(NetMessage req) throws Exception {
        String encryptedB64 = s(req.payload.get("aes_encrypted"));
        String ivB64 = s(req.payload.get("iv"));
        if (isBlank(encryptedB64) || isBlank(ivB64)) {
            throw new IllegalArgumentException("missing encrypted payload");
        }

        byte[] ciphertext = java.util.Base64.getDecoder().decode(encryptedB64);
        byte[] iv = java.util.Base64.getDecoder().decode(ivB64);
        byte[] plaintext = SecurityUtil.aesGcmDecrypt(ciphertext, sessionRsAESKey, iv);
        return new com.fasterxml.jackson.databind.ObjectMapper()
            .readValue(plaintext, MAP_STRING_OBJECT_TYPE);
    }

    private boolean printResp(NetMessage resp, String type) throws Exception {
        if (resp == null) {
            System.out.println("ERROR: no response");
            return false;
        }

        if ("ERROR".equals(resp.status)) {
            System.out.println("ERROR: " + resp.errorMessage);
            return false;
        }

        if (MessageTypes.LOGIN_REQ.equals(type)) {
            System.out.println("Login successful");
            return true;
        }

        if (MessageTypes.TOKEN_ISSUE_REQ.equals(type)) {
            System.out.println("Session started");
            return true;
        }

        if (MessageTypes.COURSE_LIST_REQ.equals(type)) {
            return true;
        }

        if (MessageTypes.ADMIN_LIST_USERS_REQ.equals(type)) {
            Object users = resp.payload.get("users");
            if (users instanceof List<?>) {
                System.out.println("Users:");
                for (Object u : (List<?>) users) {
                    System.out.println(" - " + u);
                }
            } else {
                System.out.println("Users: []");
            }
            return true;
        }

        if (MessageTypes.RESOURCE_UPDATE_REQ.equals(type)) {
            Map<String, Object> authPayload = decryptRsEncryptedPayload(resp);
            Object posts = authPayload.get("posts");
            if (posts instanceof List<?>) {
                System.out.println("Posts:");
                List<?> list = (List<?>) posts;
                if (list.isEmpty()) {
                    System.out.println(" (none)");
                } else {
                    for (Object p : list) {
                        System.out.println(" - " + p);
                    }
                }
            }
            return true;
        }

        if (MessageTypes.RESOURCE_READ_REQ.equals(type)) {
            Map<String, Object> authPayload = decryptRsEncryptedPayload(resp);
            System.out.println("Title: " + authPayload.get("fileName"));
            System.out.println("Course: " + authPayload.get("course"));
            System.out.println("Tag: " + authPayload.get("tag"));
            System.out.println("Author: " + authPayload.get("author") + " (" + authPayload.get("authorRole") + ")");
            System.out.println("Content: " + authPayload.get("content"));
            return true;
        }

        if (MessageTypes.COURSE_ENROLL_REQ.equals(type)) {
            System.out.println("User enrolled.");
            return true;
        }

        if (MessageTypes.COURSE_UNENROLL_REQ.equals(type)) {
            System.out.println("User unenrolled.");
            return true;
        }

        if (MessageTypes.COURSE_DROP_REQ.equals(type)) {
            System.out.println("Dropped course.");
            return true;
        }

        if (MessageTypes.COURSE_ROSTER_REQ.equals(type)) {
            Object rosterObj = resp.payload.get("roster");
            if (rosterObj instanceof List<?>) {
                System.out.println("Roster for " + currentCourse + ":");
                List<?> list = (List<?>) rosterObj;
                if (list.isEmpty()) {
                    System.out.println(" (none)");
                } else {
                    for (Object r : list) {
                        System.out.println(" - " + r);
                    }
                }
            }
            return true;
        }

        if (MessageTypes.COURSE_ADD_REQ.equals(type)) {
            System.out.println("Course added.");
            return true;
        }

        if (MessageTypes.COURSE_DEL_REQ.equals(type)) {
            System.out.println("Course deleted.");
            return true;
        }

        if (MessageTypes.ADMIN_CREATE_USER_REQ.equals(type)) {
            System.out.println("User created.");
            return true;
        }

        if (MessageTypes.ADMIN_DELETE_USER_REQ.equals(type)) {
            System.out.println("User deleted.");
            return true;
        }

        if (MessageTypes.RESOURCE_CREATE_REQ.equals(type)) {
            System.out.println("Post created.");
            return true;
        }

        if (MessageTypes.RESOURCE_DELETE_REQ.equals(type)) {
            System.out.println("Post deleted.");
            return true;
        }

        return true;
    }

    private void help() {
        System.out.println("Commands:");
        System.out.println("  help");
        System.out.println("  courses");
        System.out.println("  select");
        System.out.println("  whoami");
        System.out.println("  logout");
        System.out.println("  exit");
        
        if (isAdmin) {
            System.out.println();
            System.out.println("Admin:");
            System.out.println("  add course");
            System.out.println("  delete course <course>");
            System.out.println("  create user");
            System.out.println("  delete user <username>");
            System.out.println("  users");
            System.out.println("  roster");
            System.out.println("  enroll");
            System.out.println("  kick");
        } else if (currentCourse != null && isTeacher(currentCourse)) {
            System.out.println();
            System.out.println("Teacher:");
            System.out.println("  roster");
            System.out.println("  enroll");
            System.out.println("  kick");
        }

        if (!isAdmin && currentCourse != null && "student".equals(courseRoles.get(currentCourse))) {
            System.out.println();
            System.out.println("Student:");
            System.out.println("  drop <course>");
        }

        if (currentCourse != null) {
            System.out.println();
            System.out.println("Posts:");
            System.out.println("  post");
            System.out.println("  list");
            System.out.println("  listtag <tag>");
            System.out.println("  view <title>");

            if (isAdmin || isTeacher(currentCourse)) {
                System.out.println("  delete <title>");
            }
        }
    }

    private void needToken() {
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("not logged in");
        }
    }

    private void needCourse() {
        if (currentCourse == null || currentCourse.isBlank()) {
            throw new IllegalStateException("no active course selected");
        }
    }

    private void logout() {
        username = null;
        token = null;
        isAdmin = false;
        courseRoles = new HashMap<>();
        currentCourse = null;

        closeASConnection();
        closeRSConnection();
        sessionAsAESKey = null;
        clientNonce = null;
        asNonce = null;
        sessionRsAESKey = null;
        rsClientNonce = null;
        rsNonce = null;
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

        Map<String, Object> payload = mapper.readValue(payloadBytes, MAP_STRING_OBJECT_TYPE);
        long expiresAt = asLong(payload.get("expiresAt"));
        long nowSec = System.currentTimeMillis() / 1000L;
        if (expiresAt <= 0 || nowSec > expiresAt) {
            return null;
        }

        String username = s(payload.get("username"));
        String email = s(payload.get("email"));
        boolean isAdmin = asBool(payload.get("isAdmin"));
        long issuedAt = asLong(payload.get("issuedAt"));

        Map<String, String> roles = new HashMap<>();
        Object rolesObj = payload.get("courseRoles");
        if (rolesObj instanceof Map<?, ?> rm) {
            for (Map.Entry<?, ?> e : rm.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    roles.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
                }
            }
        }

        return new Models.TokenClaims(username, email, isAdmin, roles, issuedAt, expiresAt);
    }

    private static long asLong(Object o) {
        if (o instanceof Number n) return n.longValue();
        try {
            return Long.parseLong(s(o));
        } catch (Exception e) {
            return -1L;
        }
    }

    private static boolean asBool(Object o) {
        if (o instanceof Boolean b) return b;
        return "true".equalsIgnoreCase(s(o));
    }

    private static String s(Object o) {
        return o == null ? "" : String.valueOf(o);
    }
}