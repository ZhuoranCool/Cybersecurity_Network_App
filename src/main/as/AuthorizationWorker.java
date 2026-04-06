package main.as;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.*;
import java.util.regex.Pattern;
import main.common.*;
import main.common.Models.*;
import main.common.auth.RsCertificate;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

public class AuthorizationWorker extends Thread {
    private static final long AUTH_TIMESTAMP_SKEW_MS = 5 * 60 * 1000L;

    private final Socket socket;
    private final AuthorizationServer asServer;
    private javax.crypto.SecretKey sessionAESKey = null;
    private String clientNonce = null;
    private String asNonce = null;
    private boolean authenticated = false;
    private String authenticatedUser = null;

    private final ObjectMapper mapper = new ObjectMapper();
    private static final Pattern COURSE_RE = Pattern.compile("^cs\\d+$", Pattern.CASE_INSENSITIVE);

    public AuthorizationWorker(Socket socket, AuthorizationServer server) {
        this.socket = socket;
        this.asServer = server;
    }

    @Override
    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            System.out.println("[AS] Connection from " + socket.getInetAddress() + ":" + socket.getPort());

            while (true) {
                Object obj = in.readObject();

                if (obj instanceof NetMessage req) {
                    NetMessage resp = dispatch(req);
                    out.writeObject(resp);
                    out.flush();
                    continue;
                }

                if (obj instanceof SecureEnvelope env) {
                    if (sessionAESKey == null) {
                        NetMessage err = NetMessage.err("unknown", ErrorCodes.UNAUTHORIZED,
                                "secure session not established");
                        out.writeObject(err);
                        out.flush();
                        continue;
                    }

                    try {
                        byte[] plaintext = SecurityUtil.aesGcmDecrypt(env.ciphertext, sessionAESKey, env.iv);
                        NetMessage req = mapper.readValue(plaintext, NetMessage.class);

                        NetMessage resp = dispatch(req);

                        byte[] respPlain = mapper.writeValueAsBytes(resp);
                        byte[] respIv = SecurityUtil.randomBytes(12);
                        byte[] respCipher = SecurityUtil.aesGcmEncrypt(respPlain, sessionAESKey, respIv);

                        out.writeObject(new SecureEnvelope(respIv, respCipher));
                        out.flush();
                    } catch (Exception e) {
                        NetMessage err = NetMessage.err("unknown", ErrorCodes.INTERNAL,
                                "secure processing failed: " + e.getMessage());
                        out.writeObject(err);
                        out.flush();
                    }

                    continue;
                }

                break;
            }
        } catch (Exception ignored) {
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }

    private NetMessage dispatch(NetMessage req) {
        try {
            if (req == null || req.type == null) {
                return NetMessage.err(safeReqId(req), ErrorCodes.BAD_REQUEST, "missing type");
            }

            switch (req.type) {
                case MessageTypes.KEY_EXCHANGE_REQ:
                    return handleKeyExchange(req);
                case MessageTypes.REGISTER_REQ: return register(req);
                case MessageTypes.LOGIN_REQ: return login(req);
                case MessageTypes.TOKEN_ISSUE_REQ: return issueToken(req);
                case MessageTypes.TOKEN_VALIDATE_REQ: return validateToken(req);

                case MessageTypes.COURSE_LIST_REQ: return courseList(req);
                case MessageTypes.COURSE_JOIN_REQ: return courseJoin(req);
                case MessageTypes.COURSE_DROP_REQ: return courseDrop(req);
                case MessageTypes.COURSE_ROSTER_REQ: return courseRoster(req);
                case MessageTypes.COURSE_UNENROLL_REQ: return courseUnenroll(req);
                case MessageTypes.COURSE_ENROLL_REQ: return courseEnroll(req);

                case MessageTypes.COURSE_ADD_REQ: return courseAdd(req);
                case MessageTypes.COURSE_DEL_REQ: return courseDel(req);

                case MessageTypes.ADMIN_CREATE_USER_REQ: return adminCreateUser(req);
                case MessageTypes.ADMIN_DELETE_USER_REQ: return adminDeleteUser(req);
                case MessageTypes.ADMIN_MOVE_USER_REQ: return adminMoveUser(req);
                case MessageTypes.ADMIN_LIST_USERS_REQ: return adminListUsers(req);

                case MessageTypes.RS_CERT_REQUEST: return handleRsCertRequest(req);

                default:
                    return NetMessage.err(req.requestId, ErrorCodes.UNKNOWN_TYPE, "unsupported type " + req.type);
            }
        } catch (Exception e) {
            return NetMessage.err(safeReqId(req), ErrorCodes.INTERNAL, e.getMessage());
        }
    }

    private NetMessage handleRsCertRequest(NetMessage req) throws Exception {
        String rsId = s(req.payload.get("rsId"));
        String publicKeyB64 = s(req.payload.get("publicKeyB64"));
        String hostname = s(req.payload.get("hostname"));
        Object portObj = req.payload.get("port");
        Object fromObj = req.payload.get("requestValidFrom");
        Object toObj = req.payload.get("requestValidTo");

        if (isBlank(rsId) || isBlank(publicKeyB64) || isBlank(hostname)
                || !(portObj instanceof Number)
                || !(fromObj instanceof Number)
                || !(toObj instanceof Number)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "invalid certificate request");
        }

        int port = ((Number) portObj).intValue();
        long validFrom = ((Number) fromObj).longValue();
        long validTo = ((Number) toObj).longValue();

        if (port <= 0 || validTo <= validFrom) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "invalid certificate request fields");
        }

        String issuer = "AS";
        String serialNumber = java.util.UUID.randomUUID().toString();

        RsCertificate cert = new RsCertificate(
            rsId,
            issuer,
            hostname,
            port,
            publicKeyB64,
            validFrom,
            validTo,
            serialNumber,
            null
        );

        byte[] sig = SecurityUtil.rsaSignPSS(
            cert.signingPayload().getBytes(java.nio.charset.StandardCharsets.UTF_8),
            asServer.privateKey
        );
        cert.signatureB64 = java.util.Base64.getEncoder().encodeToString(sig);

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.type = MessageTypes.RS_CERT_RESPONSE;
        ok.payload.put("certificate", cert);
        return ok;
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
        byte[] decrypted = SecurityUtil.rsaDecryptOAEP(encrypted, asServer.privateKey);
        byte[] aesKeyBytes = java.util.Arrays.copyOfRange(decrypted, 0, 32);
        byte[] nonceBytes = java.util.Arrays.copyOfRange(decrypted, 32, decrypted.length);
        this.sessionAESKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
        this.clientNonce = new String(nonceBytes, java.nio.charset.StandardCharsets.UTF_8);

        //generate as nonce
        this.asNonce = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);

        //{ "as_nonce": <string>, "status": "ok" }
        java.util.Map<String, Object> respPayload = new java.util.HashMap<>();
        respPayload.put("as_nonce", asNonce);
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

    private NetMessage register(NetMessage req) throws Exception {
        String username = normalizeUsername(s(req.payload.get("username")));
        String password = s(req.payload.get("password"));
        String email = s(req.payload.get("email"));

        if (isBlank(username) || isBlank(password)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "username/password required");
        }

        synchronized (asServer) {
            if (asServer.users.containsKey(username)) {
                return NetMessage.err(req.requestId, ErrorCodes.ALREADY_EXISTS, "user exists");
            }

            asServer.users.put(username, new User(username, SecurityUtil.bcryptHash(password), email));
            asServer.accessByUser.put(username, new UserAccess(false, new java.util.HashMap<>()));
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("username", username);
        ok.payload.put("registered", true);
        return ok;
    }

    private NetMessage login(NetMessage req) throws Exception {
        if (sessionAESKey == null || isBlank(clientNonce) || isBlank(asNonce)) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "secure session not established");
        }

        Map<String, Object> authPayload = decryptEncryptedPayload(req);
        String username = normalizeUsername(s(authPayload.get("username")));
        String password = s(authPayload.get("password"));
        String providedClientNonce = s(authPayload.get("clientNonce"));
        String providedAsNonce = s(authPayload.get("asNonce"));
        Object timestampObj = authPayload.get("timestamp");

        if (isBlank(username) || isBlank(password) || !(timestampObj instanceof Number)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "invalid authentication payload");
        }
        if (!Objects.equals(clientNonce, providedClientNonce) || !Objects.equals(asNonce, providedAsNonce)) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "nonce validation failed");
        }

        long timestamp = ((Number) timestampObj).longValue();
        long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) > AUTH_TIMESTAMP_SKEW_MS) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "stale authentication request");
        }

        User user = asServer.users.get(username);
        if (user == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "invalid credentials");
        }
        boolean okPassword =
                SecurityUtil.bcryptCheck(password, user.passwordHash) ||
                passwordMatches(password, user.passwordHash);

        if (!okPassword) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "invalid credentials");
        }

        authenticated = true;
        authenticatedUser = username;

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("login", "success");
        return ok;
    }

    private NetMessage issueToken(NetMessage req) throws Exception {
        if (!authenticated || authenticatedUser == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "login required");
        }
        String username = normalizeUsername(s(req.payload.get("username")));
        if (isBlank(username)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "username required");
        }
        if (!authenticatedUser.equals(username)) {
            return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, "token request user mismatch");
        }

        User u = asServer.users.get(username);
        if (u == null) return NetMessage.err(req.requestId, ErrorCodes.NOT_FOUND, "user not found");

        UserAccess access = getOrCreateAccess(username);
        long now = System.currentTimeMillis() / 1000L;
        long exp = now + asServer.tokenTtlSec;

        TokenClaims claims = new TokenClaims(
                username,
                u.email,
                access.isAdmin,
                access.courseRoles,
                now,
                exp
        );

        String token = buildSignedToken(claims);

        synchronized (asServer) {
            asServer.tokens.put(token, claims);
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("token", token);
        ok.payload.put("expiresAt", exp);
        ok.payload.put("clientNonce", clientNonce);
        ok.payload.put("asNonce", asNonce);
        ok.payload.put("tokenAlg", "RSASSA-PSS-SHA256");
        ok.payload.put("claims", claims);
        return ok;
    }

    private NetMessage validateToken(NetMessage req) {
        String token = s(req.payload.get("token"));
        if (isBlank(token)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "token required");
        }

        TokenClaims claims = asServer.tokens.get(token);
        if (claims == null) return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "invalid token");

        long now = System.currentTimeMillis() / 1000L;
        if (now > claims.expiresAt) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "token expired");
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("claims", claims);
        return ok;
    }

    private NetMessage courseList(NetMessage req) {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("isAdmin", claims.isAdmin);

        if (claims.isAdmin) {
            List<String> allCourses = new ArrayList<>(asServer.courses.keySet());
            Collections.sort(allCourses);
            ok.payload.put("courses", allCourses);
            ok.payload.put("courseRoles", Collections.emptyMap());
        } else {
            List<String> myCourses = new ArrayList<>(claims.courseRoles.keySet());
            Collections.sort(myCourses);
            ok.payload.put("courses", myCourses);
            ok.payload.put("courseRoles", claims.courseRoles);
        }

        return ok;
    }

    private NetMessage courseJoin(NetMessage req) {
        return NetMessage.err(req.requestId,
                ErrorCodes.FORBIDDEN,
                "Self-enrollment disabled. Admin or the course teacher must enroll users.");
    }

    private NetMessage courseDrop(NetMessage req) throws Exception {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");

        String course = normalizeCourse(s(req.payload.get("course")));
        if (!isValidCourseCode(course) || !courseExists(course)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_COURSE_CODE, "bad course code");
        }

        String myRole = roleInCourse(claims, course);
        if (!"student".equals(myRole)) {
            return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, "only students can self-unenroll");
        }

        synchronized (asServer) {
            UserAccess access = getOrCreateAccess(claims.username);
            access.courseRoles.remove(course);
            asServer.accessByUser.put(claims.username, access);
            invalidateTokensForUser(claims.username);
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("course", course);
        ok.payload.put("username", claims.username);
        ok.payload.put("success", "self-unenrolled");
        return ok;
    }

    private NetMessage courseRoster(NetMessage req) {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");

        String course = normalizeCourse(s(req.payload.get("course")));
        if (!isValidCourseCode(course) || !courseExists(course)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_COURSE_CODE, "bad course code");
        }

        if (!(claims.isAdmin || "teacher".equals(roleInCourse(claims, course)))) {
            return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, "teacher/admin only");
        }

        List<String> roster = new ArrayList<>();
        for (Map.Entry<String, UserAccess> e : asServer.accessByUser.entrySet()) {
            String username = e.getKey();
            UserAccess access = e.getValue();
            if (access == null) continue;

            String role = access.courseRoles.get(course);
            if (role != null) {
                roster.add(username + " | " + role);
            }
        }
        Collections.sort(roster);

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("course", course);
        ok.payload.put("roster", roster);
        return ok;
    }

    private NetMessage courseEnroll(NetMessage req) throws Exception {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");

        String target = normalizeUsername(s(req.payload.get("username")));
        String course = normalizeCourse(s(req.payload.get("course")));
        String role = normalizeCourseRole(s(req.payload.get("role")));

        if (isBlank(target) || isBlank(course) || isBlank(role)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "username/course/role required");
        }
        if (!courseExists(course)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_COURSE_CODE, "bad course code");
        }
        if (!(claims.isAdmin || "teacher".equals(roleInCourse(claims, course)))) {
            return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, "teacher/admin only");
        }
        if ("teacher".equals(role) && !claims.isAdmin) {
            return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, "only admin can assign teacher role");
        }

        synchronized (asServer) {
            if (!asServer.users.containsKey(target)) {
                return NetMessage.err(req.requestId, ErrorCodes.NOT_FOUND, "user not found");
            }

            UserAccess targetAccess = getOrCreateAccess(target);
            String validationError = validateAssignment(targetAccess, course, role, claims.isAdmin);
            if (validationError != null) {
                return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, validationError);
            }

            targetAccess.courseRoles.put(course, role);
            asServer.accessByUser.put(target, targetAccess);
            invalidateTokensForUser(target);
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("username", target);
        ok.payload.put("course", course);
        ok.payload.put("role", role);
        ok.payload.put("success", "enrolled");
        return ok;
    }

    private NetMessage courseUnenroll(NetMessage req) throws Exception {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");

        String course = normalizeCourse(s(req.payload.get("course")));
        String target = normalizeUsername(s(req.payload.get("student")));

        if (isBlank(target) || isBlank(course)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "course/student required");
        }
        if (!courseExists(course)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_COURSE_CODE, "bad course code");
        }

        boolean allowed = claims.isAdmin || "teacher".equals(roleInCourse(claims, course));
        if (!allowed) {
            return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, "teacher/admin only");
        }

        synchronized (asServer) {
            UserAccess targetAccess = asServer.accessByUser.get(target);
            if (targetAccess == null) {
                return NetMessage.err(req.requestId, ErrorCodes.NOT_FOUND, "user not found");
            }
            if (!targetAccess.courseRoles.containsKey(course)) {
                return NetMessage.err(req.requestId, ErrorCodes.NOT_ENROLLED, "user not in course");
            }

            targetAccess.courseRoles.remove(course);
            asServer.accessByUser.put(target, targetAccess);
            invalidateTokensForUser(target);
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("success", "unenrolled");
        ok.payload.put("course", course);
        ok.payload.put("student", target);
        return ok;
    }

    private NetMessage courseAdd(NetMessage req) throws Exception {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
        }
        if (!claims.isAdmin) {
            return NetMessage.err(req.requestId, ErrorCodes.NOT_ADMIN, "admin only");
        }

        String course = normalizeCourse(s(req.payload.get("course")));
        String name = s(req.payload.get("name")).trim();

        if (!isValidCourseCode(course)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_COURSE_CODE, "bad course code");
        }
        if (isBlank(name)) {
            name = course.toUpperCase();
        }

        synchronized (asServer) {
            if (asServer.courses.containsKey(course)) {
                return NetMessage.err(req.requestId, ErrorCodes.ALREADY_EXISTS, "course already exists");
            }

            asServer.courses.put(course, new Course(course, name));
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("success", "new course added");
        ok.payload.put("course", course);
        ok.payload.put("name", name);
        return ok;
    }

    private NetMessage courseDel(NetMessage req) throws Exception {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
        }
        if (!claims.isAdmin) {
            return NetMessage.err(req.requestId, ErrorCodes.NOT_ADMIN, "admin only");
        }

        String course = normalizeCourse(s(req.payload.get("course")));
        if (!isValidCourseCode(course)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_COURSE_CODE, "bad course code");
        }

        synchronized (asServer) {
            if (!asServer.courses.containsKey(course)) {
                return NetMessage.err(req.requestId, ErrorCodes.NOT_FOUND, "course not found");
            }

            asServer.courses.remove(course);

            for (Map.Entry<String, UserAccess> e : asServer.accessByUser.entrySet()) {
                UserAccess access = e.getValue();
                if (access == null) continue;

                if (access.courseRoles.remove(course) != null) {
                    invalidateTokensForUser(e.getKey());
                }
            }

            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("success", "course deleted");
        ok.payload.put("course", course);
        return ok;
    }

    private NetMessage adminCreateUser(NetMessage req) throws Exception {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
        }
        if (!claims.isAdmin) {
            return NetMessage.err(req.requestId, ErrorCodes.NOT_ADMIN, "admin only");
        }

        String username = normalizeUsername(s(req.payload.get("username")));
        String password = s(req.payload.get("password"));
        String email = s(req.payload.get("email"));

        if (isBlank(username) || isBlank(password)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "username/password required");
        }

        synchronized (asServer) {
            if (asServer.users.containsKey(username)) {
                return NetMessage.err(req.requestId, ErrorCodes.ALREADY_EXISTS, "user exists");
            }

            asServer.users.put(username, new User(username, SecurityUtil.bcryptHash(password), email));
            asServer.accessByUser.put(username, new UserAccess(false, Collections.emptyMap()));
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("username", username);
        ok.payload.put("isAdmin", false);
        ok.payload.put("courseRoles", Collections.emptyMap());
        return ok;
    }

    private NetMessage adminDeleteUser(NetMessage req) throws Exception {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
        }
        if (!claims.isAdmin) {
            return NetMessage.err(req.requestId, ErrorCodes.NOT_ADMIN, "admin only");
        }

        String target = normalizeUsername(s(req.payload.get("username")));
        if (isBlank(target)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST, "username required");
        }
        if ("admin".equalsIgnoreCase(target)) {
            return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, "cannot delete seeded admin");
        }

        synchronized (asServer) {
            if (!asServer.users.containsKey(target)) {
                return NetMessage.err(req.requestId, ErrorCodes.NOT_FOUND, "user not found");
            }

            asServer.users.remove(target);
            asServer.accessByUser.remove(target);
            invalidateTokensForUser(target);
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("deletedUser", target);
        return ok;
    }

    private NetMessage adminMoveUser(NetMessage req) throws Exception {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
        }
        if (!claims.isAdmin) {
            return NetMessage.err(req.requestId, ErrorCodes.NOT_ADMIN, "admin only");
        }

        String target = normalizeUsername(s(req.payload.get("username")));
        String fromCourse = normalizeCourse(s(req.payload.get("fromCourse")));
        String toCourse = normalizeCourse(s(req.payload.get("toCourse")));

        if (isBlank(target) || isBlank(fromCourse) || isBlank(toCourse)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_REQUEST,
                    "username, fromCourse, and toCourse required");
        }
        if (!courseExists(fromCourse) || !courseExists(toCourse)) {
            return NetMessage.err(req.requestId, ErrorCodes.BAD_COURSE_CODE, "source or destination course missing");
        }

        synchronized (asServer) {
            if (!asServer.users.containsKey(target)) {
                return NetMessage.err(req.requestId, ErrorCodes.NOT_FOUND, "user not found");
            }

            UserAccess access = getOrCreateAccess(target);
            String currentRole = access.courseRoles.get(fromCourse);
            if (currentRole == null) {
                return NetMessage.err(req.requestId, ErrorCodes.NOT_ENROLLED, "user not in source course");
            }

            String validationError = validateAssignment(access, toCourse, currentRole, true);
            if (validationError != null) {
                return NetMessage.err(req.requestId, ErrorCodes.FORBIDDEN, validationError);
            }

            access.courseRoles.remove(fromCourse);
            access.courseRoles.put(toCourse, currentRole);

            asServer.accessByUser.put(target, access);
            invalidateTokensForUser(target);
            asServer.flush();
        }

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("username", target);
        ok.payload.put("fromCourse", fromCourse);
        ok.payload.put("toCourse", toCourse);
        return ok;
    }

    private NetMessage adminListUsers(NetMessage req) {
        TokenClaims claims = claimsFromToken(req);
        if (claims == null) {
            return NetMessage.err(req.requestId, ErrorCodes.UNAUTHORIZED, "missing/invalid token");
        }
        if (!claims.isAdmin) {
            return NetMessage.err(req.requestId, ErrorCodes.NOT_ADMIN, "admin only");
        }

        List<String> out = new ArrayList<>();
        for (String username : asServer.users.keySet()) {
            UserAccess access = asServer.accessByUser.getOrDefault(username, new UserAccess());
            out.add(username + " | admin=" + access.isAdmin + " | courseRoles=" + access.courseRoles);
        }
        Collections.sort(out);

        NetMessage ok = NetMessage.ok(req.requestId);
        ok.payload.put("users", out);
        return ok;
    }

    private TokenClaims claimsFromToken(NetMessage req) {
        String token = s(req.payload.get("token"));
        if (isBlank(token)) return null;

        TokenClaims claims = asServer.tokens.get(token);
        if (claims == null) return null;

        long now = System.currentTimeMillis() / 1000L;
        if (now > claims.expiresAt) return null;

        return claims;
    }

    private UserAccess getOrCreateAccess(String username) {
        UserAccess access = asServer.accessByUser.get(username);
        if (access == null) {
            access = new UserAccess();
        }
        if (access.courseRoles == null) {
            access.courseRoles = new java.util.HashMap<>();
        }
        return access;
    }

    private void invalidateTokensForUser(String username) {
        Iterator<Map.Entry<String, TokenClaims>> it = asServer.tokens.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, TokenClaims> e = it.next();
            TokenClaims claims = e.getValue();
            if (claims != null && claims.username != null && claims.username.equalsIgnoreCase(username)) {
                it.remove();
            }
        }
    }

    private String roleInCourse(TokenClaims claims, String course) {
        if (claims == null || claims.courseRoles == null) return null;
        return claims.courseRoles.get(normalizeCourse(course));
    }

    private String validateAssignment(UserAccess access, String course, String newRole, boolean isAdminActor) {
        if (access == null) return "invalid user access";
        if (access.isAdmin) return "cannot modify admin course roles";
        if (!isValidCourseCode(course) || !courseExists(course)) return "bad course code";
        if (!List.of("student", "ta", "teacher").contains(newRole)) return "bad role";

        String existingRoleThisCourse = access.courseRoles.get(course);
        if (existingRoleThisCourse != null && existingRoleThisCourse.equals(newRole)) {
            return null;
        }

        boolean hasTeacherAnywhere = false;
        boolean hasStudentAnywhere = false;
        boolean hasTaAnywhere = false;

        for (String role : access.courseRoles.values()) {
            if ("teacher".equals(role)) hasTeacherAnywhere = true;
            if ("student".equals(role)) hasStudentAnywhere = true;
            if ("ta".equals(role)) hasTaAnywhere = true;
        }

        if ("teacher".equals(newRole)) {
            if (!isAdminActor) return "only admin can assign teacher role";
            if (hasStudentAnywhere || hasTaAnywhere) return "teacher cannot also be student/ta in another course";
            return null;
        }

        if ("student".equals(newRole) || "ta".equals(newRole)) {
            if (hasTeacherAnywhere) return "teacher cannot also be student/ta in another course";
        }

        return null;
    }

    private static String normalizeCourse(String c) {
        return c == null ? "" : c.trim().toLowerCase();
    }

    private static String normalizeUsername(String u) {
        return u == null ? "" : u.trim().toLowerCase();
    }

    private static String normalizeCourseRole(String r) {
        String x = r == null ? "" : r.trim().toLowerCase();
        return switch (x) {
            case "student", "ta", "teacher" -> x;
            default -> "";
        };
    }

    private boolean courseExists(String course) {
        return course != null && asServer.courses.containsKey(course.toLowerCase());
    }

    private boolean isValidCourseCode(String course) {
        return course != null && COURSE_RE.matcher(course).matches();
    }

    private static String safeReqId(NetMessage m) {
        return m == null ? "unknown" : m.requestId;
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

    private boolean passwordMatches(String password, String storedHash) {
        if (isBlank(storedHash)) {
            return false;
        }
        if (storedHash.startsWith("$2")) {
            return SecurityUtil.bcryptCheck(password, storedHash);
        }
        return Objects.equals(storedHash, SecurityUtil.sha256(password));
    }

    private String buildSignedToken(TokenClaims claims) throws Exception {
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("username", claims.username);
        payload.put("email", claims.email);
        payload.put("isAdmin", claims.isAdmin);
        payload.put("courseRoles", claims.courseRoles);
        payload.put("issuedAt", claims.issuedAt);
        payload.put("expiresAt", claims.expiresAt);
        payload.put("clientNonce", clientNonce);
        payload.put("asNonce", asNonce);
        payload.put("jti", UUID.randomUUID().toString());

        byte[] payloadBytes = mapper.writeValueAsBytes(payload);
        byte[] signature = SecurityUtil.rsaSignPSS(payloadBytes, asServer.privateKey);

        String payloadB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBytes);
        String sigB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        return payloadB64 + "." + sigB64;
    }
}