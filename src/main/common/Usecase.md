# Common Module Use Case Document  
**Project:** Phase 2  
**Module:** `src/common/`  

---

## 1. Purpose

This document defines the professional design intent and operational use cases for the shared `common` module.  
The `common` module provides reusable protocol contracts, data models, error standards, persistence helpers, and security utilities used by:

- Authorization Server (AS)
- Resource Server (RS)
- Client CLI


---

## 2. Scope

This document covers the following files:

- `NetMessage.java`
- `MessageTypes.java`
- `ErrorCodes.java`
- `Models.java`
- `Persistence.java`
- `SecurityUtil.java`

It includes:

1. Functional responsibilities  
2. File-level use cases  
3. Cross-file interaction map  
4. Non-functional qualities (reliability, maintainability, security)  
5. Operational risks and controls

---

## 3. Design Principles of `common`

1. **Single source of truth** for protocol and error semantics  
2. **Low coupling / high cohesion** between AS, RS, and Client  
3. **Deterministic error handling** for easier debugging and grading verification  
4. **Safe persistence defaults** for restart reliability  

---

## 4. File-by-File Professional Use Cases

---

## 4.1 `NetMessage.java`

### Responsibility
Defines the standard request/response envelope for all network communication.

### Key Elements
- `type`: operation identifier  
- `requestId`: correlation identifier  
- `status`: response status (`OK`/`ERROR`)  
- `errorCode`, `errorMessage`: normalized failure reporting  
- `payload`: flexible data body (`Map<String,Object>`)

### Use Cases

#### UC-COM-001: Build outbound request from Client
- **Actor:** ClientCLI  
- **Precondition:** User enters command  
- **Flow:**  
  1. Client calls `NetMessage.request(<message_type>)`  
  2. Client adds request parameters in `payload`  
  3. Client sends serialized object over socket  
- **Postcondition:** AS/RS receives a consistent request envelope

#### UC-COM-002: Build standardized server success response
- **Actor:** AS Worker / RS Worker  
- **Flow:**  
  1. Server processes request  
  2. Server returns `NetMessage.ok(requestId)` with payload  
- **Postcondition:** Client receives structured success output

#### UC-COM-003: Build standardized server error response
- **Actor:** AS Worker / RS Worker  
- **Flow:**  
  1. Validation/policy/internal issue detected  
  2. Server returns `NetMessage.err(requestId, code, message)`  
- **Postcondition:** Client receives machine-readable and human-readable failure

---

## 4.2 `MessageTypes.java`

### Responsibility
Central registry for all legal operation names used in dispatch.

### Key Constants
- AS: `REGISTER_REQ`, `LOGIN_REQ`, `TOKEN_ISSUE_REQ`, `TOKEN_VALIDATE_REQ`
- RS: `RESOURCE_CREATE_REQ`, `RESOURCE_READ_REQ`, `RESOURCE_UPDATE_REQ`, `RESOURCE_DELETE_REQ`

### Use Cases

#### UC-COM-004: Compile-time-safe request typing
- **Actor:** Client/AS/RS developers  
- **Flow:**  
  1. Import constants from `MessageTypes`  
  2. Use constants in request creation and switch dispatch  
- **Postcondition:** String typo risk is minimized across modules

#### UC-COM-005: Deterministic routing in workers
- **Actor:** AS Worker / RS Worker  
- **Flow:**  
  1. Worker reads `req.type`  
  2. Switches by `MessageTypes` constant  
- **Postcondition:** Correct handler method is executed for each request

---

## 4.3 `ErrorCodes.java`

### Responsibility
Defines normalized error categories for all server failures.

### Key Constants
- `BAD_REQUEST`
- `UNAUTHORIZED`
- `FORBIDDEN`
- `NOT_FOUND`
- `ALREADY_EXISTS`
- `INTERNAL`
- `UNKNOWN_TYPE`

### Use Cases

#### UC-COM-006: Validation failure reporting
- **Actor:** AS Worker / RS Worker  
- **Flow:**  
  1. Required field missing/invalid  
  2. Return `BAD_REQUEST`  
- **Postcondition:** Client can distinguish bad input from auth failures

#### UC-COM-007: Authorization failure reporting
- **Actor:** RS Worker  
- **Flow:**  
  1. Token invalid/expired → `UNAUTHORIZED`  
  2. Authenticated but not allowed by policy → `FORBIDDEN`  
- **Postcondition:** Correct access-control semantics are visible to user/tester

#### UC-COM-008: Unsupported operation detection
- **Actor:** AS Worker / RS Worker  
- **Flow:**  
  1. `req.type` not recognized  
  2. Return `UNKNOWN_TYPE`  
- **Postcondition:** Protocol misuse is explicitly signaled

---

## 4.4 `Models.java`

### Responsibility
Shared serializable domain model definitions used by AS/RS and transported in payloads.

### Model Classes
- `User`
- `RoleGroup`
- `TokenClaims`
- `Resource`

### Use Cases

#### UC-COM-009: Persist user identity state
- **Actor:** AS  
- **Flow:**  
  1. On register, create `User`  
  2. Store in AS map and persist  
- **Postcondition:** User identity survives restart

#### UC-COM-010: Persist authorization attributes
- **Actor:** AS  
- **Flow:**  
  1. On register/admin operation, assign `RoleGroup`  
  2. Persist in roles map  
- **Postcondition:** Role/group policy inputs are durable

#### UC-COM-011: Transport token claims to policy engine
- **Actor:** AS and RS  
- **Flow:**  
  1. AS validates token and returns `TokenClaims`  
  2. RS evaluates owner/role/group access  
- **Postcondition:** RS decisions are based on validated identity context

#### UC-COM-012: Persist resource protection metadata
- **Actor:** RS  
- **Flow:**  
  1. On create/update, maintain `Resource` (owner/groups/content/timestamp)  
  2. Save in resource database  
- **Postcondition:** Resource state and security metadata remain consistent

---

## 4.5 `Persistence.java`

### Responsibility
Provides generic file persistence utilities with atomic write behavior.

### Methods
- `saveAtomic(obj, path)`
- `loadOrDefault(path, defaultValue)`

### Use Cases

#### UC-COM-013: Safe state save for mutable maps
- **Actor:** AS/RS  
- **Flow:**  
  1. Serialize object to `<path>.tmp`  
  2. Move temp file to target path atomically  
- **Postcondition:** Reduced risk of partial-write corruption

#### UC-COM-014: Startup recovery
- **Actor:** AS/RS startup routines  
- **Flow:**  
  1. Attempt load from persisted file  
  2. On missing/corrupt file, use default object  
- **Postcondition:** Service starts predictably and safely

---

## 4.6 `SecurityUtil.java`

### Responsibility
Provides centralized cryptographic helper(s) for credential safety.

### Methods
- `sha256(String text)`

### Use Cases

#### UC-COM-015: Password hashing at registration
- **Actor:** AS  
- **Flow:**  
  1. Receive plaintext password  
  2. Hash via `SecurityUtil.sha256()`  
  3. Store hash in `User.passwordHash`  
- **Postcondition:** Plaintext password is never persisted

#### UC-COM-016: Password verification at login
- **Actor:** AS  
- **Flow:**  
  1. Hash incoming login password  
  2. Compare with stored hash  
- **Postcondition:** Authentication is deterministic and non-plaintext

---

## 5. Cross-File Interaction Map

This section shows how files in `common` collaborate during core operations.

---

## 5.1 Register Flow (Client → AS)

1. **ClientCLI** builds `NetMessage.request(MessageTypes.REGISTER_REQ)`  
2. Payload includes username/password/email/roles/groups  
3. **AS Worker** receives `NetMessage` and dispatches by `MessageTypes`  
4. **SecurityUtil** hashes password  
5. **Models.User** and **Models.RoleGroup** are created/stored  
6. **Persistence.saveAtomic** writes user and role stores  
7. **AS Worker** returns `NetMessage.ok` or `NetMessage.err(ErrorCodes...)`

**Files touched:**  
`NetMessage` → `MessageTypes` → `SecurityUtil` → `Models` → `Persistence` → `ErrorCodes`

---

## 5.2 Login Flow (Client → AS)

1. Client sends `LOGIN_REQ` in `NetMessage`  
2. AS dispatches by `MessageTypes`  
3. AS hashes incoming password using `SecurityUtil`  
4. Compares against persisted `Models.User.passwordHash`  
5. Returns success/failure with `NetMessage` + `ErrorCodes`

**Files touched:**  
`NetMessage` → `MessageTypes` → `SecurityUtil` → `Models` → `ErrorCodes`

---

## 5.3 Token Issue / Validate Flow (Client/RS ↔ AS)

### Issue
1. Client sends `TOKEN_ISSUE_REQ`  
2. AS reads user + role/group (`Models`)  
3. AS creates `Models.TokenClaims` with expiry timestamps  
4. AS persists token store using `Persistence`  
5. AS returns token + claims via `NetMessage`

### Validate
1. RS sends `TOKEN_VALIDATE_REQ` to AS with token  
2. AS checks token existence and expiry  
3. AS returns claims or error code

**Files touched:**  
`NetMessage` → `MessageTypes` → `Models` → `Persistence` → `ErrorCodes`

---

## 5.4 Protected Resource Access Flow (Client → RS, RS → AS)

1. Client sends resource request (`RESOURCE_*_REQ`) in `NetMessage`  
2. RS dispatches by `MessageTypes`  
3. RS calls AS token validation (`TOKEN_VALIDATE_REQ`)  
4. AS returns `Models.TokenClaims`  
5. RS checks policy with claims + `Models.Resource` metadata  
6. RS persists mutations with `Persistence` (create/update/delete)  
7. RS returns `NetMessage.ok` or `NetMessage.err(ErrorCodes.FORBIDDEN/...)`

**Files touched:**  
`NetMessage` ↔ `MessageTypes` ↔ `Models` ↔ `ErrorCodes` ↔ `Persistence`

---

## 5.5 Startup / Shutdown Reliability Flow (AS and RS)

### Startup
1. Service loads map(s) via `Persistence.loadOrDefault`  
2. If file unavailable/corrupt, default empty maps are used

### Shutdown / Mutation
1. Service calls `Persistence.saveAtomic`  
2. State is flushed to disk using atomic replacement

**Files touched:**  
`Persistence` + `Models`

---

## 6. Dependency Summary Matrix

| Common File | AS Uses | RS Uses | Client Uses | Primary Function |
|---|---|---|---|---|
| `NetMessage.java` | Yes | Yes | Yes | Unified request/response envelope |
| `MessageTypes.java` | Yes | Yes | Yes | Operation name constants |
| `ErrorCodes.java` | Yes | Yes | Indirectly (reads responses) | Standardized error taxonomy |
| `Models.java` | Yes | Yes | Indirectly (receives claims/resources) | Shared domain objects |
| `Persistence.java` | Yes | Yes | No | Durable atomic state storage |
| `SecurityUtil.java` | Yes | No (in current design) | No | Password hashing utility |

---


