# Task Execution Platform – Executor Component
## Product Requirements Document (PRD)

### 1. Purpose
Define the requirements for the **Executor**, a Python service responsible for fetching, executing, and reporting the outcome of backend jobs submitted through the Task Execution Platform.

### 2. Background
The platform enables users to submit diverse long-running tasks via a web UI or REST API. Jobs are enqueued in Redis and processed asynchronously. The Executor is the critical runtime component that guarantees reliable execution, status tracking, and logging for every job.

### 3. Scope
*This PRD covers only the Executor service.* It excludes the API layer, web UI, and any infrastructure automation beyond what directly affects the Executor.

### 4. Stakeholders
| Role | Responsibility |
| ---- | -------------- |
| Product Owner | Defines requirements & acceptance criteria |
| Engineering Team | Designs & implements the Executor |
| DevOps | Deploys & monitors the service |
| End-users | Submit jobs and view statuses |

### 5. Definitions
| Term | Meaning |
| ---- | ------- |
| Job | A user-submitted task containing `class.method` and parameters |
| Status | One of `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED` |
| Executor | Python process that executes a single job at a time |

#### Supported Task Categories & Examples
* **Scheduled Batch Tasks (Daily Updates)**: e.g., nightly data warehouse refresh, report generation.
* **Ad-hoc On-Demand Tasks**: user-triggered jobs such as reindexing a single item or flushing a cache entry.
* **Real-time Event-Driven Tasks**: small payload operations kicked off by application events (e.g., send transactional email, recompute statistics).
* **Data Pipeline & ETL Tasks**: ingest, transform, and load datasets from external sources.
* **Maintenance & Housekeeping Tasks**: health checks, orphan record cleanup, log rotation.

Each task submission **must** include a `task_type` field so the Executor can apply type-specific defaults such as priority, timeout, and retry policy.

### 6. Functional Requirements
FR-1 Job Retrieval
* The Executor **must** fetch jobs from a Redis list/stream using blocking pop (e.g., `BRPOP`).
* Retrieval latency **must** be ≤ 100 ms on average.

FR-2 Dynamic Resolution & Execution
* The payload **must** include the fully-qualified Python `module.Class.method` and JSON-serialisable `parameters`.
* The Executor **must** dynamically import the module, instantiate the class (if needed), and invoke the method with the provided parameters.
* Execution occurs in the same process space; future versions may allow sandboxing (out-of-scope for v1).

FR-3 Status Lifecycle
* On fetch → update status to `RUNNING` in the persistent DB.
* On success → `COMPLETED`, storing return value (≤ 10 KB) and timestamps.
* On exception → `FAILED`, capturing stack trace & logs.

FR-4 Retry & Idempotency
* Failed jobs **must** be retried up to *N* times (configurable, default = 3) with exponential back-off.
* Retried job executions **must** be idempotent; Executor will flag duplicates but still attempt if no idempotency key is provided.

FR-5 Logging & Auditing
* Standard output and errors **must** be captured and streamed to the central logger (stdout for Docker, structured JSON).
* Execution metadata **must** be written to the DB for later inspection.

FR-6 Heartbeats & Health
* Executor **must** emit a heartbeat metric every 5 s indicating liveness.
* A `/healthz` HTTP endpoint **must** report `200 OK` if the Executor can reach Redis & DB.

FR-7 Graceful Shutdown
* On SIGTERM, Executor **must** finish the current job (or mark as `FAILED` after timeout) before exit.

FR-8 Configuration
* All runtime parameters (Redis URL, DB URL, concurrency, retry count) **must** be configurable via environment variables with sane defaults.

### 7. Non-Functional Requirements
| Category | Requirement |
| -------- | ----------- |
| Reliability | ≥ 99.9 % successful job execution across restarts |
| Scalability | Horizontal scaling to 100+ concurrent Executors |
| Performance | Start job ≤ 500 ms after queue; average CPU ≤ 70 % |
| Security | Input validation, restricted dynamic import path, no arbitrary code execution outside whitelisted modules |
| Maintainability | PEP 8 compliance; modular code |

### 8. Technical Requirements
1. **Language & Runtime**: Python 3.11+.
2. **Dependencies**:
   * `redis>=5.0` for queue interaction
   * `SQLAlchemy>=2.0` for DB writes
   * `pydantic` for payload validation
   * `structlog`, `loguru` or similar for logging


### 9. Out of Scope
* UI/UX for job submission.
* Advanced sandboxing or multi-language execution.
* Autoscaling policies (handled by platform layer).

### 10. Success Metrics
| Metric | Target |
| ------ | ------ |
| Mean time from queue to RUNNING | < 500 ms |
| Job execution success rate | ≥ 99.9 % |
| Error log coverage | 100 % of failed jobs contain stack traces |

### 11. Assumptions
* Redis and DB services are highly available.
* Jobs are designed to be idempotent or tolerate retries.

### 12. Risks & Mitigations
| Risk | Impact | Mitigation |
| ---- | ------ | ---------- |
| Long-running or hanging jobs | Block Executor | Implement job timeout & watchdog |
| Malformed payloads | Runtime errors | Validate with `pydantic` before execution |
| Dynamic import security | Code injection | Restrict import search paths & sign job definitions |

### 13. Milestones & Timeline (T-shirt sizing)
1. **Week 1** Design & skeleton codebase
2. **Week 2** Redis integration & job execution
3. **Week 3** DB status updates & logging
4. **Week 4** Retries, heartbeats, graceful shutdown
5. **Week 5** Documentation and production readiness

### 14. References
* Original User Requirements Document (`product.md`)
* Redis documentation – Streams & Lists
* Python PEP 8 & PEP 249

### 15. Initial Task & Packaging Conventions
#### 15.1 Seed Task – `f5portalupdate`
* **Category**: Data Pipeline & ETL Task
* **Entry point**: `tasks.f5portalupdate.main:run`
* **Expected runtime**: ≤ 2 h (`timeout_seconds = 7200`)
* **Parameters**:
  * `customer_id` (int, required)
  * `full_rebuild` (bool, default =`false`)
* **Output**: JSON summary `{ "updated_rows": <int>, "customer_id": <int> }`
* **Retry policy**: 3 attempts with exponential back-off per §FR-4.

#### 15.2 Task Package Layout
All task implementations **MUST** reside under the top-level Python package `tasks` (whitelisted by the Executor’s `ALLOWED_MODULES`).

Recommended structure for multi-file tasks:
```text
tasks/
  f5portalupdate/
    __init__.py          # package marker
    main.py              # orchestration + run() entry-point
    steps/
      extract.py
      transform.py
      load.py
```
Only the public `run()` callable is referenced by the Executor; sub-modules remain internal.

Example job payload fragment:
```json
{
  "module_path": "tasks.f5portalupdate.main",
  "class_name": null,
  "method_name": "run"
}
```

#### 15.3 Future Tasks
Additional tasks must follow the same packaging convention. If a new top-level namespace is needed, update the `ALLOWED_MODULES` environment variable accordingly.

---
*Document version 1.0 – Generated on* {{ DATE_PLACEHOLDER }} 
