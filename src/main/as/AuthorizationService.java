package main.as;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import main.common.ErrorCodes;
import main.common.Models;
import main.common.NetMessage;
import main.common.SecurityUtil;

public class AuthorizationService {
    private final Map<String, Models.User> users;
    private final Map<String, Models.UserAccess> accessByUser;
    private final Map<String, Models.TokenClaims> tokens;
    private final long tokenTtlSec;

    public AuthorizationService(
            Map<String, Models.User> users,
            Map<String, Models.UserAccess> accessByUser,
            Map<String, Models.TokenClaims> tokens,
            long tokenTtlSec
    ) {
        this.users = users;
        this.accessByUser = accessByUser;
        this.tokens = tokens;
        this.tokenTtlSec = tokenTtlSec;
    }

    public synchronized NetMessage register(String requestId, String username, String password, String email) {
        return NetMessage.err(
                requestId,
                ErrorCodes.FORBIDDEN,
                "Registration disabled. Admin must create users."
        );
    }

    public NetMessage login(String requestId, String username, String password) {
        if (isBlank(username) || isBlank(password)) {
            return NetMessage.err(requestId, ErrorCodes.BAD_REQUEST, "username/password required");
        }

        username = username.trim().toLowerCase();

        Models.User u = users.get(username);
        if (u == null) {
            return NetMessage.err(requestId, ErrorCodes.UNAUTHORIZED, "invalid credentials");
        }

        String hash = SecurityUtil.sha256(password);
        if (!Objects.equals(hash, u.passwordHash)) {
            return NetMessage.err(requestId, ErrorCodes.UNAUTHORIZED, "invalid credentials");
        }

        NetMessage ok = NetMessage.ok(requestId);
        ok.payload.put("login", "success");
        return ok;
    }

    public synchronized NetMessage issueToken(String requestId, String username) {
        if (isBlank(username)) {
            return NetMessage.err(requestId, ErrorCodes.BAD_REQUEST, "username required");
        }

        username = username.trim().toLowerCase();

        Models.User u = users.get(username);
        if (u == null) {
            return NetMessage.err(requestId, ErrorCodes.NOT_FOUND, "user not found");
        }

        Models.UserAccess access = accessByUser.getOrDefault(
                username,
                new Models.UserAccess(false, Collections.emptyMap())
        );

        long now = System.currentTimeMillis() / 1000L;
        long exp = now + tokenTtlSec;

        Models.TokenClaims claims = new Models.TokenClaims(
                username,
                u.email,
                access.isAdmin,
                access.courseRoles,
                now,
                exp
        );

        String token = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        tokens.put(token, claims);

        NetMessage ok = NetMessage.ok(requestId);
        ok.payload.put("token", token);
        ok.payload.put("claims", claims);
        return ok;
    }

    public NetMessage validateToken(String requestId, String token) {
        if (isBlank(token)) {
            return NetMessage.err(requestId, ErrorCodes.BAD_REQUEST, "token required");
        }

        Models.TokenClaims claims = tokens.get(token);
        if (claims == null) {
            return NetMessage.err(requestId, ErrorCodes.UNAUTHORIZED, "invalid token");
        }

        long now = System.currentTimeMillis() / 1000L;
        if (now > claims.expiresAt) {
            return NetMessage.err(requestId, ErrorCodes.UNAUTHORIZED, "token expired");
        }

        NetMessage ok = NetMessage.ok(requestId);
        ok.payload.put("claims", claims);
        return ok;
    }

    private boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    public static AuthorizationService withEmptyStores(long tokenTtlSec) {
        return new AuthorizationService(
                new ConcurrentHashMap<>(),
                new ConcurrentHashMap<>(),
                new ConcurrentHashMap<>(),
                tokenTtlSec
        );
    }

    public Map<String, Models.User> getUsers() {
        return users;
    }

    public Map<String, Models.UserAccess> getAccessByUser() {
        return accessByUser;
    }

    public Map<String, Models.TokenClaims> getTokens() {
        return tokens;
    }
}