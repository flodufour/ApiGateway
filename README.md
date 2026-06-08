# API Gateway

Single entry point for all client requests — handles JWT validation, request routing, rate limiting, and user identity injection toward downstream microservices. Authentication is delegated to a microservice named AuthService.

---

## Stack

- **ASP.NET Core 9** — Web API
- **YARP** (`Yarp.ReverseProxy 2.3`) — reverse proxy by Microsoft
- **JWT RS256** — asymmetric token validation via JWKS (`Microsoft.AspNetCore.Authentication.JwtBearer 9.x`)

---

## Responsibilities

| Responsibility | Detail |
|---|---|
| Routing | Forward each path to the correct microservice |
| JWT validation | Validate tokens on protected routes via JWKS |
| Identity injection | Inject `X-User-Id` and `X-User-Email` headers for downstream services |
| Header stripping | Strip client-provided identity headers on **all** routes |
| Correlation IDs | Propagate or generate `X-Correlation-ID` across all services |
| Rate limiting | Per-IP fixed window: 300 req/min, returns `429` |
| CORS | Manage allowed origins |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` |
| HSTS | Enabled in production |
| Error handling | Global exception handler — no stack traces leaked to clients |
| Health checks | `GET /health` (liveness), `GET /health/ready` (readiness) |

---

## Architecture

```
Client  →  ApiGateway  →  AuthService          (auth routes — public)
                       →  OtherService_1       (protected — JWT required)
                       →  OtherService_2       (protected — JWT required)
```

- The Gateway is the **only entry point** — no client ever contacts a microservice directly
- The Gateway validates the JWT — downstream microservices never see or validate tokens
- **One codebase deployed multiple times** with different environment configs (one instance per application)

---

## JWT Validation — AuthService Integration

The Gateway fetches the public key automatically from AuthService's JWKS endpoint at startup:

```
GET https://authservice/.well-known/jwks.json
```

No shared secret. No manual key distribution. If the key rotates on AuthService, the Gateway re-fetches automatically.

Validated on every token:
- **Issuer** — must match `Auth:Issuer`
- **Audience** — must match `Auth:Audience`
- **Lifetime** — `exp` claim must be in the future
- **Signature** — RS256, signed by AuthService's private key

HTTPS metadata validation is disabled in development (`RequireHttpsMetadata = false`) and enforced in production.

---

## Identity Injection

After JWT validation, the Gateway injects the user identity into every forwarded protected request:

```
X-User-Id: <sub claim from JWT>
X-User-Email: <email claim from JWT>
```

Downstream microservices read these trusted headers directly — they never need to parse or validate a JWT.

**Important:** Incoming `X-User-Id` and `X-User-Email` headers from clients are stripped on **every route** (public and protected) before forwarding. Re-injection only happens on routes with an `AuthorizationPolicy`. This prevents impersonation even on public routes.

---

## Correlation IDs

Every request gets an `X-Correlation-ID` header:

- If the client sends one, it is accepted and forwarded as-is
- If not, a new UUID is generated

The value is:
1. Stored in `HttpContext.Items["CorrelationId"]`
2. Added to the response headers so the client can correlate logs
3. Forwarded to every downstream service via YARP transform

Use this ID to trace a single request across all services in your log aggregator.

---

## Rate Limiting

Per-IP fixed window: **300 requests per minute**. Excess requests receive `429 Too Many Requests` immediately, before JWT validation runs.

To adjust limits, modify `Program.cs`:

```csharp
new FixedWindowRateLimiterOptions
{
    Window = TimeSpan.FromMinutes(1),
    PermitLimit = 300,
    QueueLimit = 0,
}
```

---

## Auth Routes (forwarded to AuthService)

| Method | Route | Auth |
|---|---|---|
| POST | `/auth/register` | Public |
| POST | `/auth/verify-email` | Public |
| POST | `/auth/resend-verification` | Public |
| POST | `/auth/login` | Public |
| POST | `/auth/refresh` | Public |
| POST | `/auth/logout` | Public |
| POST | `/auth/forgot-password` | Public |
| POST | `/auth/reset-password` | Public |
| GET | `/auth/me` | Bearer |
| GET | `/.well-known/jwks.json` | Public |

All other routes require a valid JWT.

---

## Project Structure

```
ApiGateway/
├── .gitignore                         ← ignores bin/, obj/, appsettings.*.json, secrets
├── ApiGateway/
│   ├── Program.cs                     ← all configuration, no controllers
│   ├── appsettings.json               ← tracked, no secrets
│   └── appsettings.Development.json   ← gitignored, local dev values
```

YARP handles all routing via configuration — no controllers needed.

---

## Configuration

### `appsettings.json`

```json
{
  "Auth": {
    "Authority": "",
    "Issuer": "AuthService",
    "Audience": "ApiGateway"
  },
  "Cors": {
    "AllowedOrigins": []
  },
  "ReverseProxy": {
    "Routes": {
      "auth-route": {
        "ClusterId": "auth-cluster",
        "Match": { "Path": "/auth/{**catch-all}" }
      },
      "wellknown-route": {
        "ClusterId": "auth-cluster",
        "Match": { "Path": "/.well-known/{**catch-all}" }
      },
      "service-route": {
        "ClusterId": "service-cluster",
        "AuthorizationPolicy": "default",
        "Match": { "Path": "/service/{**catch-all}" }
      }
    },
    "Clusters": {
      "auth-cluster": {
        "HttpRequest": { "Timeout": "00:00:30" },
        "Destinations": {
          "dest": { "Address": "http://authservice:5121/" }
        }
      },
      "service-cluster": {
        "HttpRequest": { "Timeout": "00:00:30" },
        "Destinations": {
          "dest": { "Address": "http://service:5200/" }
        }
      }
    }
  }
}
```

### `appsettings.Development.json` (gitignored)

```json
{
  "Auth": {
    "Authority": "http://localhost:5121",
    "Issuer": "AuthService",
    "Audience": "ApiGateway"
  },
  "Cors": {
    "AllowedOrigins": ["http://localhost:3000", "http://localhost:5173"]
  }
}
```

### Production (environment variables)

```
Auth__Authority=https://authservice.yourdomain.com
Auth__Issuer=AuthService
Auth__Audience=ApiGateway
Cors__AllowedOrigins__0=https://yourapp.com
```

ASP.NET Core merges config sources in order — environment variables override files.

---

## ASP.NET Core Pipeline Order

```
Exception handler       — catches all unhandled exceptions, returns { "error": "..." }
HSTS                    — production only
HTTPS redirect
CORS                    — must be before auth so OPTIONS preflight always succeeds
Security headers        — X-Content-Type-Options, X-Frame-Options, Referrer-Policy
Correlation ID          — accept from client or generate new UUID, echo in response
Rate limiter            — per-IP, before JWT validation to avoid wasted work
Authentication          — validates JWT, populates HttpContext.User
Authorization           — enforces AuthorizationPolicy on protected routes
/health                 — liveness probe (no dependencies)
/health/ready           — readiness probe (checks AuthService JWKS)
YARP reverse proxy      — strips identity headers, injects from JWT, forwards request
```

---

## Startup Validation

The app throws at startup if required config is missing:

```csharp
// Auth:Authority missing
throw new InvalidOperationException(
    "Auth:Authority must be configured. Use environment variable Auth__Authority in production.");

// Cors:AllowedOrigins empty in production
throw new InvalidOperationException(
    "Cors:AllowedOrigins must be configured in production. Use Cors__AllowedOrigins__0=https://yourapp.com");
```

This prevents the gateway from silently running in a broken state.

---

## Health Checks

| Endpoint | Type | Checks |
|---|---|---|
| `GET /health` | Liveness | Gateway process is alive |
| `GET /health/ready` | Readiness | Gateway can reach AuthService JWKS (5s timeout) |

Both endpoints are anonymous (no JWT required).

Use `/health` for liveness probes (restart on failure) and `/health/ready` for readiness probes (remove from load balancer until AuthService is reachable).

---

## Docker / Kubernetes

### Docker Compose

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:80/health"]
  interval: 30s
  timeout: 5s
  retries: 3
```

### Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 80
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /health/ready
    port: 80
  initialDelaySeconds: 10
  periodSeconds: 15
```

### Multiple deployments — one codebase, different configs

```yaml
gateway-app-a:
  image: apigateway:latest
  environment:
    - Auth__Authority=http://authservice-a:5121
    - Cors__AllowedOrigins__0=https://app-a.com

gateway-app-b:
  image: apigateway:latest
  environment:
    - Auth__Authority=http://authservice-b:5121
    - Cors__AllowedOrigins__0=https://app-b.com
```

---

## Adding a New Downstream Service

No code changes needed. Add a route and cluster to `appsettings.json`:

```json
"Routes": {
  "my-service-route": {
    "ClusterId": "my-service-cluster",
    "AuthorizationPolicy": "default",
    "Match": { "Path": "/myservice/{**catch-all}" }
  }
},
"Clusters": {
  "my-service-cluster": {
    "HttpRequest": { "Timeout": "00:00:30" },
    "Destinations": {
      "dest": { "Address": "http://myservice:5300/" }
    }
  }
}
```

The downstream service receives `X-User-Id` and `X-User-Email` from the gateway — no JWT knowledge required.

---

## Key Points

1. `/.well-known/jwks.json` must be reachable by the Gateway at startup — never put it behind auth
2. Identity headers are stripped on **all** routes, re-injected only on protected ones — clients can never forge identity
3. `appsettings.Development.json` is gitignored — never commit environment-specific config or secrets
4. One codebase, deployed N times — each instance configured via environment variables
5. Downstream services only read `X-User-Id` and `X-User-Email` — they never see or validate a JWT
6. Rate limiting runs before JWT validation — malicious traffic is rejected cheaply

---

## Running Locally

```bash
dotnet run
```

| Endpoint | URL |
|---|---|
| Liveness | `http://localhost:5000/health` |
| Readiness | `http://localhost:5000/health/ready` |
