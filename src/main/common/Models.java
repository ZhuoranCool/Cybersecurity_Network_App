package main.common;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class Models {

    public static class User implements Serializable {
        private static final long serialVersionUID = 1L;

        public String username;
        public String passwordHash;
        public String email;

        public User(String username, String passwordHash, String email) {
            this.username = username;
            this.passwordHash = passwordHash;
            this.email = email;
        }
    }

    public static class UserAccess implements Serializable {
        private static final long serialVersionUID = 1L;

        // only true for the single seeded admin
        public boolean isAdmin;

        // courseCode -> role ("student", "ta", "teacher")
        public Map<String, String> courseRoles = new HashMap<>();

        public UserAccess() {}

        public UserAccess(boolean isAdmin, Map<String, String> courseRoles) {
            this.isAdmin = isAdmin;
            if (courseRoles != null) {
                for (Map.Entry<String, String> e : courseRoles.entrySet()) {
                    if (e.getKey() != null && e.getValue() != null) {
                        this.courseRoles.put(
                                e.getKey().trim().toLowerCase(),
                                e.getValue().trim().toLowerCase()
                        );
                    }
                }
            }
        }
    }

    public static class TokenClaims implements Serializable {
        private static final long serialVersionUID = 1L;

        public String username;
        public String email;
        public boolean isAdmin;

        // courseCode -> role ("student", "ta", "teacher")
        public Map<String, String> courseRoles = new HashMap<>();

        public long issuedAt;
        public long expiresAt;

        public TokenClaims(String username, String email, boolean isAdmin,
                           Map<String, String> courseRoles,
                           long issuedAt, long expiresAt) {
            this.username = username;
            this.email = email;
            this.isAdmin = isAdmin;
            if (courseRoles != null) {
                for (Map.Entry<String, String> e : courseRoles.entrySet()) {
                    if (e.getKey() != null && e.getValue() != null) {
                        this.courseRoles.put(
                                e.getKey().trim().toLowerCase(),
                                e.getValue().trim().toLowerCase()
                        );
                    }
                }
            }
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
        }
    }

    public static class Resource implements Serializable {
        private static final long serialVersionUID = 1L;

        public String resourceId;
        public String owner;
        public String course;
        public String content;
        public long updatedAt;

        public Resource(String resourceId, String owner, String course, String content, long updatedAt) {
            this.resourceId = resourceId;
            this.owner = owner;
            this.course = course;
            this.content = content;
            this.updatedAt = updatedAt;
        }
    }

    public static class Course implements Serializable {
        private static final long serialVersionUID = 1L;

        public String code;
        public String name;

        public Course(String code, String name) {
            this.code = code == null ? "" : code.trim().toLowerCase();
            this.name = name == null ? "" : name.trim();
        }
    }
}