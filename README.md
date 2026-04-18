# E-Commerce Authentication Microservice

## Overview

Centralized authentication and authorization service for an e-commerce platform. Acts as the identity gatekeeper — all other microservices (product, order, payment) trust this service to verify user identity and permissions.

Answers two questions for every request:
1. **Authentication**: "Who are you?" (email + password → JWT)
2. **Authorization**: "What can you do?" (role-based: CUSTOMER, SELLER, ADMIN)

## Architecture

```
Client → HTTP Request
  → Tomcat (request size limits)
  → JwtAuthenticationFilter (JWT parse → Redis check → SecurityContext)
  → SecurityConfig (permitAll? authenticated? hasRole?)
  → Controller (validate input → call service → build response)
  → Service (business logic → @Transactional DB writes)
  → Repository (JPA → PostgreSQL via HikariCP)
  → TokenService (Redis via Lettuce pool)
  → ApiResponse envelope → JSON response
  → GlobalExceptionHandler (catches any failures)
```

## High-Level Design Decisions

### Stateless JWT + Redis for Revocation
- JWT is self-contained (userId, email, roles embedded) — downstream services verify without calling auth service.
- Redis stores active tokens for revocation capability (logout, password reset, role change).
- Trade-off: JWT is stateless (scalable) but can't be revoked natively. Redis adds "just enough state" for revocation.

### Two-Token System (Access + Refresh)
- Access token: JWT, 15 minutes. Sent on every API call. Contains claims.
- Refresh token: Opaque string, 7 days. Used only to get new access token. Stored in Redis.
- Refresh token rotation: each refresh invalidates the old token and issues a new one. Detects token theft.

### Redis-Only Token Storage (No DB)
- Token validation is the HOT PATH — every API call in the platform hits it.
- Redis: ~1-3ms per lookup, 100K+ ops/sec. PostgreSQL: ~5-20ms, ~5K ops/sec.
- Tokens are ephemeral (15min-7days). Redis TTL handles auto-cleanup. No cron jobs.
- BRD Section 7.2 explicitly defines Redis as the token store.

### BCrypt Strength 12
- ~250ms per hash. Intentionally slow — makes brute force impractical (~4 attempts/sec/core).
- Only used on login and registration (cold path). Token validation (hot path) never touches BCrypt.

### Fail-Closed Security
- If Redis is down, all token validation fails → 401 on every request.
- Security over availability. A compromised token shouldn't work just because Redis is temporarily unavailable.
- Production mitigation: Redis Sentinel/Cluster for automatic failover.

## Low-Level Design Decisions

### Single JWT Parse in Filter Chain
- Old approach: `validateToken()` + `getUserId()` + `getRoles()` = 3 HMAC-SHA256 verifications.
- Current: `parseTokenSafe()` returns Claims object, all fields read from memory. ~2ms vs ~6ms.

### Separate DB Transactions from Redis Operations
- `AuthService.login()` is NOT @Transactional. DB writes (`handleFailedLogin`, `resetFailedAttempts`) have their own @Transactional.
- Redis calls (`storeAccessToken`, `generateRefreshToken`) are outside transactions.
- Rationale: different failure domains. If Redis fails, DB changes should persist (and vice versa).

### Double Defense Against Duplicate Emails
1. App-level `existsByEmail()` check (fast path, catches 99.9%)
2. DB unique constraint catch (`DataIntegrityViolationException`) for race conditions (0.1%)

### Anti-Enumeration Patterns
- Login: same error message for "email not found" and "wrong password".
- Forgot password: always returns 200 regardless of email existence.
- Registration role field: `@Pattern` rejects "ADMIN" at DTO level — never reaches service.

### Response Projections
- `UserResponse.from()` — public view (registration, self-profile). No admin fields.
- `UserResponse.adminView()` — includes status, accountLocked, failedLoginAttempts, lockedAt.
- `@JsonInclude(NON_NULL)` — null fields excluded from JSON. Clean responses.

### Email Service Abstraction
- `EmailService` interface with `ConsoleEmailService` POC implementation.
- Production swap: create `SesEmailService implements EmailService` with `@Primary`. Zero changes to PasswordService.

## Data Model

```
┌──────────┐     ┌─────────────┐     ┌──────────┐
│  users   │────<│ user_roles  │>────│  roles   │
├──────────┤     ├─────────────┤     ├──────────┤
│ user_id  │     │ user_id(FK) │     │ role_id  │
│ name     │     │ role_id(FK) │     │ role_name│
│ email    │     └─────────────┘     └──────────┘
│ password │
│ hash     │     Redis Keys:
│ status   │     ┌─────────────────────────────┐
│ failed   │     │ user_token:{userId} → JWT   │
│ _attempts│     │ refresh_token:{token}→userId │
│ locked   │     │ reset_token:{token} → userId│
│ locked_at│     └─────────────────────────────┘
│ created  │
│ updated  │
└──────────┘
```

## API Endpoints

| Method | Endpoint | Access | Status | Description |
|--------|----------|--------|--------|-------------|
| POST | `/api/v1/user/register` | Public | 201 | Register new user |
| POST | `/api/v1/login` | Public | 200 | Login, get access + refresh tokens |
| POST | `/api/v1/auth/refresh` | Public | 200 | Refresh token rotation |
| POST | `/api/v1/logout` | Auth | 200 | Revoke tokens |
| POST | `/api/v1/user/forgot_password` | Public | 200 | Request password reset |
| POST | `/api/v1/user/reset_password` | Public | 200 | Reset password + unlock |
| GET | `/api/v1/auth/validate` | Public | 200 | Validate token for downstream services |
| GET | `/api/v1/admin/users` | Admin | 200 | List users (paginated) |
| GET | `/api/v1/admin/users/{id}` | Admin | 200 | Get user details |
| POST | `/api/v1/admin/users/{id}/roles` | Admin | 200 | Add role to user |
| DELETE | `/api/v1/admin/users/{id}/roles/{role}` | Admin | 200 | Remove role from user |
| POST | `/api/v1/admin/users/{id}/unlock` | Admin | 200 | Unlock locked account |

## Configuration

All config externalized via environment variables (12-Factor App):

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | localhost | PostgreSQL host |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | auth_db | Database name |
| `DB_USERNAME` | auth_user | DB username |
| `DB_PASSWORD` | auth_pass | DB password |
| `REDIS_HOST` | localhost | Redis host |
| `REDIS_PORT` | 6379 | Redis port |
| `JWT_SECRET` | (dev default) | HMAC-SHA256 key (min 32 bytes) |
| `JWT_EXPIRATION_MS` | 900000 | Access token TTL (15 min) |
| `REFRESH_TOKEN_EXPIRATION_MS` | 604800000 | Refresh token TTL (7 days) |
| `ADMIN_EMAIL` | admin@system.com | Default admin email |
| `ADMIN_PASSWORD` | Admin@123 | Default admin password |
| `SERVER_PORT` | 8080 | Application port |

## Running

```bash
# Start infrastructure
docker-compose up -d

# Build and run
./mvnw clean package -DskipTests
java -jar target/auth-service-0.0.1-SNAPSHOT.jar
```

## Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Language | Java 17 | LTS, modern features (records, sealed classes, pattern matching) |
| Framework | Spring Boot 3.5 | Production-grade, massive ecosystem |
| Security | Spring Security + JJWT | Industry standard for JWT + RBAC |
| Database | PostgreSQL 16 | UUID support, JSONB, production-grade |
| Token Store | Redis 7 | Sub-ms latency, TTL auto-cleanup, 100K+ ops/sec |
| Build | Maven | Dependency management, reproducible builds |
| Container | Docker | Consistent environments, horizontal scaling |

## Production Upgrade Path

| Current (POC) | Production |
|---------------|------------|
| `ddl-auto: update` | Flyway/Liquibase migrations |
| Console email | AWS SES / SendGrid |
| Single Redis node | Redis Sentinel / Cluster |
| HMAC-SHA256 (symmetric) | RSA/EC (asymmetric — downstream services verify without secret) |
| No rate limiting | Rate limiting on login + forgot_password |
| No tests | Unit + integration tests |
| No API docs | Swagger/OpenAPI |
| Env var secrets | AWS Secrets Manager / Vault |
