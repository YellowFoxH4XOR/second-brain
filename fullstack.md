+++
id = 'fullstack-rules'
title = 'Full-Stack Development Rules (Angular + Python)'
scope = 'workspace'
target_audience = 'All Agents'
status = 'active'
+++

# Full-Stack Development Rules (Angular + Python)

> These rules ensure seamless collaboration and technical excellence across the front-end (Angular) and back-end (Python/FastAPI) layers of our platform.

## 1. API Design & Contract
- **Contract-First**: Define or update the **OpenAPI 3.1** spec before coding. Store specs in `/api-specs/{version}/openapi.yaml`.
- **Single Source of Truth**: Code generation for TypeScript services and Pydantic models **must** come from the OpenAPI schema to prevent drift (use `openapi-generator-cli`).
- **Versioning Strategy**: Major breaking changes bump the API version (`v1` → `v2`) and expose under `/api/v{n}`. Minor changes are backward-compatible.
- **HTTP Semantics**: Use proper status codes (`201 CREATED`, `204 NO_CONTENT`, etc.) and follow the Richardson Maturity Model level 2+ (resources + verbs).

## 2. Authentication & Authorization
- **JWT with Refresh Flow**: Issue short-lived access tokens (≤ 15 min) and refresh tokens stored in `HttpOnly` secure cookies.
- **Role-Based Access Control**: Annotate FastAPI routes with dependency-injected `Depends(has_role(...))` checks. Mirror roles in Angular guards.
- **CSRF Protection**: Angular JWT cookie requests must include CSRF tokens via custom header (e.g., `X-CSRF-Token`). FastAPI validates token per request.

## 3. Data Validation & Serialization
- **Backend**: Validate all inbound payloads with **Pydantic v2** models (`from pydantic import BaseModel`).
- **Frontend**: Use generated **Zod** schemas (via `zod-to-ts`) for runtime validation before hitting the API.

## 4. Error Handling & Observability
- **Error Envelope**: All API errors follow the pattern:
  ```jsonc
  {
    "error": {
      "code": "RESOURCE_NOT_FOUND",
      "message": "Invoice not found",
      "details": {}
    }
  }
  ```
- **Global Angular Interceptor**: Maps error envelopes to user-friendly toast notifications.
- **Structured Logging**: Backend logs JSON via `structlog`; front-end logs via Google Analytics/Datadog RUM with anonymized user IDs.
- **Tracing**: Use OpenTelemetry instrumentation (`@opentelemetry/api` for Angular, `opentelemetry-instrumentation-fastapi` for Python) to correlate traces across tiers.

## 5. Build & CI/CD
- **Monorepo**: Use Nx or Turborepo for incremental builds; tasks are cached and parallelized in CI.
- **Lint → Test → Build**: Pipeline stages in this exact order. Fail fast on lint or unit test errors.
- **Docker Images**: Multi-stage builds; slim runtime images (`python:3.11-alpine`, `nginx:alpine` for SSR) ≤ 200 MB.
- **Blue-Green Deploys**: All production deployments use blue-green strategy with automated rollback on failed smoke tests.

## 6. Performance Budgets
- **Frontend**: Bundle ≤ 250 kB gzipped for initial load; set Webpack performance budget warnings.
- **Backend**: P99 latency ≤ 300 ms for primary endpoints under 1k RPS load.
- **Database**: Index queries > 100 ms; review with `EXPLAIN ANALYZE`.

## 7. Security Checklist (Cross-Tier)
- Enforce **HTTPS** everywhere; HSTS max-age ≥ 6 months.
- Implement **CORS** with allow-list per environment.
- Use **OWASP Dependency-Check** for Python and `npm audit` for Angular dependencies.
- Rotate secrets with HashiCorp Vault; never store secrets in Git.

## 8. Internationalization & Localization
- Backend returns i18n keys, not literal strings.
- Angular consumes keys via `@ngx-translate/core`; fallback language is `en-US`.

## 9. Documentation & Runbooks
- Update `/docs/ADR/` (Architectural Decision Records) for any significant architectural change.
- Provide runbooks in `/docs/runbooks/{service}.md` for on-call engineers.

---

_Together, these rules guarantee a resilient, coherent, and delightful full-stack experience._ 