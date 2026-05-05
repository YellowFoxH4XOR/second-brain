# Async Task Architecture: Technical Writeup

**Resolving API Lag Under High Concurrent Load on a Single VMware Aria VM**

Stack: FastAPI · Celery · Redis · Python

---

## 1. Problem Statement

A production application running on a single VMware Aria VM serves 200–300 concurrent users. When any user initiates a task that takes 3–4 minutes to complete, the current implementation — background threads or asyncio coroutines — runs that task inside the same OS process as the FastAPI request handlers. This causes measurable latency spikes and degraded response times for every other user on the platform.

### Core symptom

Long-running tasks share CPU, memory, and the Python GIL with the API request handlers. At 200–300 concurrent users, any task that burns compute for 3–4 minutes is effectively taxing the same pool of resources that synchronous endpoints depend on for fast responses.

### 1.1 Why asyncio alone doesn't fix it

asyncio is cooperative multitasking: coroutines voluntarily yield control. If a long task contains CPU-bound code — data transformation, file parsing, model inference, or heavy loops — it holds the event loop until that code completes. No other coroutine in the same process can run during that time.

Even tasks that are primarily I/O-bound (database queries, external API calls) cause problems at scale: each awaited coroutine occupies a connection slot, and 200–300 users running 3–4 minute tasks simultaneously exhaust the connection pool and degrade the thread pool used by SQLAlchemy or other sync drivers.

### 1.2 Why background threads don't fix it either

Python's Global Interpreter Lock (GIL) prevents true parallel execution of Python bytecode. Thread-based background jobs compete with request handler threads for the GIL, causing unpredictable latency spikes. Memory usage also grows as each background thread adds its own stack.

---

## 2. Solution Overview

The fix is process isolation: move the long-running logic entirely out of the FastAPI process into a separate worker process that the OS schedules independently. Communication between the two processes is handled by a message queue backed by Redis — which is already present on this VM.

### The full flow after the change:

1. User initiates a task via the front-end.
2. The FastAPI request handler validates the request, writes a job to the Redis queue, and returns a 202 Accepted response with a `task_id` — this takes under 100ms.
3. The Celery worker process, running independently, picks up the job from the queue and executes the 3–4 minute logic in its own memory space.
4. The worker writes the result (or error) back to Redis under the `task_id`.
5. The front-end polls `GET /tasks/{task_id}` every few seconds. FastAPI reads from Redis and returns the status.
6. When status is `SUCCESS`, the front-end receives the result and updates the UI.

### Key insight

The API server and the worker are now separate OS processes. The OS scheduler manages them independently. A 3–4 minute Celery task does not consume any resources from the Uvicorn worker processes — there is zero interference between them at the Python level.

---

## 3. Architecture on a Single VM

All four components coexist on the same VMware Aria VM. Each runs as a separate OS process managed by systemd:

| Component | Role |
|-----------|------|
| **Uvicorn / Gunicorn** | FastAPI ASGI server. Handles all HTTP traffic. Never executes task logic. Lightweight and fast. |
| **Celery worker** | Dedicated worker process. Pulls jobs from Redis, runs the 3–4 minute logic, writes results. CPU/memory isolated from the API server. |
| **Redis (existing)** | Acts as the message broker (queue) and result backend. Uses two separate DB indices to keep queue and results separate. |
| **AppDatabase (existing)** | Unchanged. The Celery worker can still write to it directly if the task produces database records as its output. |

### 3.1 Process isolation mechanics

Because Celery workers run in a separate process, they have:

- Their own Python interpreter instance, not subject to the same GIL as the API server.
- Independent memory heap — a memory leak in a task cannot crash the API server.
- Configurable CPU affinity via `taskset` if further isolation is needed.
- Independent restart cycles via systemd, so a crashed worker doesn't affect API availability.

---

## 4. Implementation

### 4.1 Celery configuration (celery_app.py)

The Celery instance connects to the existing Redis on the VM. Two separate Redis DB indices are used to prevent queue entries from colliding with cached result data:

```python
from celery import Celery

celery_app = Celery(
    "worker",
    broker="redis://localhost:6379/0",   # queue
    backend="redis://localhost:6379/1",  # results
    include=["tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=3600,          # discard results from Redis after 1 hour
    worker_prefetch_multiplier=1, # one task at a time per worker process
    task_acks_late=True,          # only ack after the task finishes (safer retries)
    worker_max_tasks_per_child=200,  # recycle worker processes to prevent memory leaks
)
```

**Configuration notes:**

- `worker_prefetch_multiplier=1` — each worker process takes exactly one task at a time. Prevents a slow task from blocking others in the same worker.
- `task_acks_late=True` — the task is only acknowledged (removed from the queue) after it finishes. If the worker crashes mid-task, the job re-queues automatically.
- `worker_max_tasks_per_child=200` — the worker process is recycled every 200 tasks, preventing memory accumulation from long-running processes.
- `result_expires=3600` — results are evicted from Redis after 1 hour, preventing unbounded memory growth.

### 4.2 Task definition (tasks.py)

The existing 3–4 minute logic moves into a Celery task function decorated with `@celery_app.task`. The `bind=True` argument gives access to `self` for retry control:

```python
from celery_app import celery_app

@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def run_long_task(self, payload: dict):
    """
    Your 3-4 minute logic lives here, completely isolated from the API process.
    `bind=True` gives you access to `self` for retries and task metadata.
    """
    try:
        # --- replace everything below with your actual work ---
        import time
        time.sleep(5)   # simulating heavy work
        result = {"output": f"processed {payload}"}
        # -------------------------------------------------------
        return result

    except Exception as exc:
        # Celery will retry up to max_retries times before marking FAILURE
        raise self.retry(exc=exc)
```

**Retry behaviour:** if the task raises an unhandled exception, Celery retries it up to `max_retries` times with a 10-second delay. After the final retry, the task is marked `FAILURE` and the error is stored in Redis for the status endpoint to return.

### 4.3 FastAPI endpoints (main.py)

The existing endpoint that ran the task synchronously or kicked off a background coroutine is replaced by two endpoints:

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from celery.result import AsyncResult
from tasks import run_long_task

app = FastAPI()

class TaskRequest(BaseModel):
    # Replace with your actual input fields
    data: dict

class TaskStatus(BaseModel):
    task_id: str
    status: str          # PENDING | STARTED | SUCCESS | FAILURE | RETRY
    result: dict | None = None
    error: str | None = None

@app.post("/tasks", status_code=202)
def submit_task(request: TaskRequest):
    """
    Accepts the request, enqueues the work, and returns immediately.
    The front-end gets a task_id to poll with.
    """
    task = run_long_task.delay(request.data)
    return {"task_id": task.id}

@app.get("/tasks/{task_id}", response_model=TaskStatus)
def get_task_status(task_id: str):
    """
    The front-end polls this every few seconds.
    Returns status + result once the worker is done.
    """
    result = AsyncResult(task_id)

    if result.state == "PENDING":
        return TaskStatus(task_id=task_id, status="PENDING")

    if result.state == "STARTED":
        return TaskStatus(task_id=task_id, status="STARTED")

    if result.state == "SUCCESS":
        return TaskStatus(task_id=task_id, status="SUCCESS", result=result.result)

    if result.state == "FAILURE":
        return TaskStatus(
            task_id=task_id,
            status="FAILURE",
            error=str(result.result),
        )

    if result.state == "RETRY":
        return TaskStatus(task_id=task_id, status="RETRY")

    raise HTTPException(status_code=500, detail=f"Unknown task state: {result.state}")
```

**Key points:**

- The submit endpoint does one thing: call `.delay()` to enqueue the task and return the task ID. The entire endpoint runs in under 5ms regardless of task complexity.
- The status endpoint reads from Redis — it does not touch the worker or the task logic.

### 4.3a FastAPI endpoints for ServiceNow + Ansible (your use case)

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from celery.result import AsyncResult
from tasks import deploy_via_servicenow_ansible

app = FastAPI()

class DeploymentRequest(BaseModel):
    description: str
    implementation_plan: str
    target_hosts: list[str]
    deployment_config: dict

class TaskStatus(BaseModel):
    task_id: str
    status: str  # PENDING | STARTED | SUCCESS | FAILURE | RETRY
    result: dict | None = None
    error: str | None = None

@app.post("/api/deploy", status_code=202)
def submit_deployment(request: DeploymentRequest):
    """
    Submit a ServiceNow + Ansible deployment task.
    Returns immediately with task_id for polling.
    """
    task = deploy_via_servicenow_ansible.delay(request.dict())
    return {"task_id": task.id}

@app.get("/api/tasks/{task_id}", response_model=TaskStatus)
def get_deployment_status(task_id: str):
    """
    Poll for deployment status.
    Returns PENDING/STARTED while in progress.
    Returns SUCCESS with change number + job ID when done.
    Returns FAILURE with error message if anything went wrong.
    """
    result = AsyncResult(task_id)

    if result.state == "PENDING":
        return TaskStatus(task_id=task_id, status="PENDING")

    if result.state == "STARTED":
        return TaskStatus(task_id=task_id, status="STARTED")

    if result.state == "SUCCESS":
        return TaskStatus(
            task_id=task_id, 
            status="SUCCESS", 
            result=result.result  # {'change_number': 'CHG...', 'job_id': 123, ...}
        )

    if result.state == "FAILURE":
        return TaskStatus(
            task_id=task_id,
            status="FAILURE",
            error=str(result.result),
        )

    if result.state == "RETRY":
        return TaskStatus(task_id=task_id, status="RETRY")

    raise HTTPException(status_code=500, detail=f"Unknown task state: {result.state}")
```

### 4.4 Task implementation example: ServiceNow + Ansible orchestration

This is the exact pattern for your use case: create a change in ServiceNow, wait for approval, trigger Ansible playbook, wait for completion, write to database.

```python
import time
import requests
from celery_app import celery_app

@celery_app.task(bind=True, max_retries=5, default_retry_delay=10)
def deploy_via_servicenow_ansible(self, change_data: dict):
    """
    1. Create change in ServiceNow
    2. Poll ServiceNow until change is approved/ready
    3. Trigger Ansible playbook
    4. Poll Ansible until playbook completes
    5. Write results to database
    """
    try:
        # ─── STEP 1: Create ServiceNow change ──────────────────────────────
        snow_url = "https://your-instance.service-now.com/api/now/table/change_request"
        snow_headers = {
            "Authorization": f"Bearer {SERVICENOW_TOKEN}",
            "Content-Type": "application/json"
        }
        
        change_payload = {
            "short_description": change_data.get("description"),
            "type": "Standard",
            "assignment_group": "DevOps",
            "implementation_plan": change_data.get("implementation_plan"),
        }
        
        snow_response = requests.post(snow_url, json=change_payload, headers=snow_headers)
        snow_response.raise_for_status()
        change_record = snow_response.json()["result"]
        change_id = change_record["sys_id"]
        change_number = change_record["number"]
        
        print(f"Created ServiceNow change: {change_number}")
        
        # ─── STEP 2: Poll ServiceNow until change is approved ─────────────
        max_wait = 300  # 5 minutes
        elapsed = 0
        poll_interval = 10
        
        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval
            
            # Check change status
            check_url = f"{snow_url}/{change_id}"
            check_response = requests.get(check_url, headers=snow_headers)
            check_response.raise_for_status()
            current_state = check_response.json()["result"]["state"]
            
            print(f"ServiceNow change {change_number} state: {current_state}")
            
            # state codes: draft=0, under_review=1, approved=2, rejected=-1, etc.
            if current_state == "2":  # approved
                print(f"Change {change_number} approved, proceeding to Ansible")
                break
            elif current_state == "-1":  # rejected
                raise Exception(f"Change {change_number} was rejected")
        else:
            raise Exception(f"Change approval timeout after {max_wait}s")
        
        # ─── STEP 3: Trigger Ansible playbook ──────────────────────────────
        ansible_url = "https://your-aap.example.com/api/v2/job_templates/42/launch/"
        ansible_headers = {
            "Authorization": f"Bearer {ANSIBLE_TOKEN}",
            "Content-Type": "application/json"
        }
        
        playbook_payload = {
            "extra_vars": {
                "servicenow_change_id": change_id,
                "target_hosts": change_data.get("target_hosts"),
                "deployment_config": change_data.get("deployment_config"),
            }
        }
        
        ansible_response = requests.post(
            ansible_url, json=playbook_payload, headers=ansible_headers
        )
        ansible_response.raise_for_status()
        job_id = ansible_response.json()["job"]
        
        print(f"Launched Ansible job: {job_id}")
        
        # ─── STEP 4: Poll Ansible until playbook completes ────────────────
        max_wait = 1200  # 20 minutes for playbook
        elapsed = 0
        poll_interval = 15
        
        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval
            
            job_url = f"https://your-aap.example.com/api/v2/jobs/{job_id}/"
            job_response = requests.get(job_url, headers=ansible_headers)
            job_response.raise_for_status()
            job_data = job_response.json()
            
            job_status = job_data["status"]
            print(f"Ansible job {job_id} status: {job_status}")
            
            # status: new, pending, waiting, running, error, failed, success, etc.
            if job_status in ["success", "error", "failed", "canceled"]:
                playbook_success = job_status == "success"
                playbook_output = job_data.get("stdout", "")
                break
        else:
            raise Exception(f"Ansible playbook timeout after {max_wait}s")
        
        if not playbook_success:
            raise Exception(f"Ansible job {job_id} failed with status {job_status}")
        
        # ─── STEP 5: Write results to database ─────────────────────────────
        from database import db, DeploymentRecord
        
        deployment = DeploymentRecord(
            servicenow_change_id=change_id,
            servicenow_change_number=change_number,
            ansible_job_id=job_id,
            status="completed",
            deployment_config=change_data.get("deployment_config"),
            ansible_output=playbook_output,
            timestamp=datetime.now(),
        )
        db.session.add(deployment)
        db.session.commit()
        
        return {
            "status": "success",
            "change_number": change_number,
            "job_id": job_id,
            "deployment_record_id": deployment.id,
        }

    except Exception as exc:
        # Log the error, then retry
        print(f"Task failed: {exc}")
        raise self.retry(exc=exc)
```

**Key patterns:**

- **ServiceNow polling loop**: checks the change state every 10 seconds up to 5 minutes. Fails fast if rejected.
- **Ansible polling loop**: checks job status every 15 seconds up to 20 minutes.
- **Database write**: happens only after both ServiceNow and Ansible complete successfully.
- **Retries**: if ServiceNow or Ansible API calls fail (network glitch, timeout), Celery retries the entire task automatically.
- **Extra vars**: sensitive config and host lists are passed to Ansible via `extra_vars`, keeping them out of logs.

### 4.5 Front-end polling (Angular + TypeScript)

The Angular front-end replaces its blocking wait with a lightweight polling loop:

```typescript
// deployment.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, interval, throwError } from 'rxjs';
import { switchMap, takeWhile, tap, catchError } from 'rxjs/operators';

export interface DeploymentRequest {
  description: string;
  implementation_plan: string;
  target_hosts: string[];
  deployment_config: object;
}

export interface TaskStatus {
  task_id: string;
  status: string; // PENDING | STARTED | SUCCESS | FAILURE | RETRY
  result?: any;
  error?: string;
}

@Injectable({ providedIn: 'root' })
export class DeploymentService {
  constructor(private http: HttpClient) {}

  // Submit the deployment task and get a task_id back immediately
  submitDeployment(request: DeploymentRequest): Observable<{ task_id: string }> {
    return this.http.post<{ task_id: string }>('/api/deploy', request);
  }

  // Poll for task status every 3 seconds
  pollTaskStatus(taskId: string): Observable<TaskStatus> {
    return interval(3000).pipe(
      switchMap(() => this.http.get<TaskStatus>(`/api/tasks/${taskId}`)),
      // Stop polling once we hit a terminal state
      takeWhile(
        (status) => status.status !== 'SUCCESS' && status.status !== 'FAILURE',
        true // Include the final value (SUCCESS or FAILURE)
      ),
      tap((status) => {
        if (status.status === 'SUCCESS' || status.status === 'FAILURE') {
          console.log('Deployment finished:', status);
        }
      }),
      catchError((error) => {
        console.error('Error polling task status:', error);
        return throwError(() => error);
      })
    );
  }

  // Wrapper: submit task and auto-poll until done
  deployAndWait(request: DeploymentRequest): Observable<TaskStatus> {
    return this.submitDeployment(request).pipe(
      switchMap((response) => this.pollTaskStatus(response.task_id))
    );
  }
}
```

**Component usage:**

```typescript
// deployment.component.ts
import { Component } from '@angular/core';
import { DeploymentService } from './deployment.service';

@Component({
  selector: 'app-deployment',
  templateUrl: './deployment.component.html',
})
export class DeploymentComponent {
  isDeploying = false;
  deploymentStatus = '';
  deploymentError: string | null = null;
  deploymentResult: any = null;

  constructor(private deploymentService: DeploymentService) {}

  startDeployment() {
    this.isDeploying = true;
    this.deploymentStatus = 'Submitting deployment...';
    this.deploymentError = null;
    this.deploymentResult = null;

    const request = {
      description: 'Deploy new release to production',
      implementation_plan: 'Rolling deployment across 3 zones',
      target_hosts: ['prod-web-01', 'prod-web-02', 'prod-web-03'],
      deployment_config: {
        version: '2.5.1',
        strategy: 'rolling',
        healthcheck_timeout: 300,
      },
    };

    this.deploymentService.deployAndWait(request).subscribe({
      next: (status) => {
        console.log('Status update:', status);
        
        if (status.status === 'PENDING' || status.status === 'RETRY') {
          this.deploymentStatus = 'Waiting in queue...';
        } else if (status.status === 'STARTED') {
          this.deploymentStatus = 'ServiceNow change submitted, waiting for approval...';
        } else if (status.status === 'SUCCESS') {
          this.deploymentStatus = 'Deployment completed successfully!';
          this.deploymentResult = status.result;
          this.isDeploying = false;
        } else if (status.status === 'FAILURE') {
          this.deploymentStatus = 'Deployment failed';
          this.deploymentError = status.error || 'Unknown error';
          this.isDeploying = false;
        }
      },
      error: (err) => {
        this.deploymentError = err.message || 'Network error during deployment';
        this.isDeploying = false;
      },
    });
  }
}
```

**Template:**

```html
<!-- deployment.component.html -->
<div class="deployment-panel">
  <button (click)="startDeployment()" [disabled]="isDeploying">
    {{ isDeploying ? 'Deploying...' : 'Start Deployment' }}
  </button>

  <div *ngIf="isDeploying" class="status">
    <p>{{ deploymentStatus }}</p>
    <app-spinner></app-spinner>
  </div>

  <div *ngIf="deploymentResult" class="success">
    <h3>✓ Deployment Complete</h3>
    <p>ServiceNow Change: {{ deploymentResult.change_number }}</p>
    <p>Ansible Job ID: {{ deploymentResult.job_id }}</p>
  </div>

  <div *ngIf="deploymentError" class="error">
    <h3>✗ Deployment Failed</h3>
    <p>{{ deploymentError }}</p>
  </div>
</div>
```

**Key Angular patterns:**

- `deployAndWait()` chains the submit and poll in a single observable stream using `switchMap`.
- `interval(3000)` polls every 3 seconds; `takeWhile()` stops once a terminal state is reached.
- The template updates reactively as `status` changes (PENDING → STARTED → SUCCESS).
- Network failures during polling are caught by the `catchError` operator.

**Polling strategy:** Polling every 3 seconds works well for ServiceNow changes (typically approve/reject within minutes) and Ansible playbooks (run 3–20 minutes). At 300 concurrent users, this generates ~100 status requests per second against the `GET /api/tasks/{id}` endpoint — each request is a single Redis GET, completing in under 2ms. The load is negligible.

---

## 5. Concurrency Tuning

The Celery worker is started with a concurrency flag that controls how many tasks run in parallel within the worker process group. The right value depends on what the task actually does:

| Task type | Recommended concurrency | Rationale | Example command |
|-----------|------------------------|-----------|-----------------|
| **CPU-bound** | `cores − 1` | Heavy computation, file parsing, data transformation, ML inference | `celery -A celery_app worker --concurrency=3` (on a 4-core VM) |
| **I/O-bound** | `16–32+` | Waiting on DB queries, external HTTP calls, file reads | `celery -A celery_app worker --concurrency=16 --pool=gevent` |
| **Mixed** | `cores × 2` | Some CPU work, some I/O waiting | `celery -A celery_app worker --concurrency=8` |

**For gevent (I/O-bound):** Install with `pip install gevent`. The gevent pool uses cooperative coroutines rather than OS threads, allowing hundreds of concurrent I/O waits with minimal memory overhead.

### Reserve headroom for the API server

Always leave at least 1–2 CPU cores unreserved for the Uvicorn/Gunicorn processes. On a 4-core VM with CPU-bound tasks, set `--concurrency=2` or `--concurrency=3`, not 4. The API server's response time degrades sharply when the worker saturates all cores.

---

## 6. Process Management with systemd

The Celery worker must survive VM reboots and auto-restart after crashes. The recommended approach is a systemd service unit:

```ini
[Unit]
Description=Celery worker for FastAPI app
After=network.target redis.service

[Service]
User=appuser
WorkingDirectory=/path/to/your/app
ExecStart=celery -A celery_app worker --loglevel=info --concurrency=4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Save this as `/etc/systemd/system/celery-worker.service`, then enable and start it:

```bash
systemctl enable celery-worker
systemctl start celery-worker
systemctl status celery-worker
```

The `Restart=always` directive ensures that if a task causes the worker to crash, systemd brings it back after 5 seconds. In-flight tasks at crash time will be re-queued by Celery (because `task_acks_late=True`) and retried automatically.

---

## 7. Task State Reference

Celery defines five task states returned by the status endpoint. Understanding these helps implement correct front-end behaviour:

| State | Meaning |
|-------|---------|
| **PENDING** | Task has been enqueued but not yet picked up by a worker. Normal state when all workers are busy. |
| **STARTED** | A worker has picked up the task and begun execution. Only emitted if `task_track_started=True` is set. |
| **SUCCESS** | Task completed without error. The `result` field contains the return value. |
| **FAILURE** | Task raised an unhandled exception after exhausting all retries. The `error` field contains the exception message. |
| **RETRY** | Task failed and is waiting to be retried. Visible between retry attempts. |

The front-end should treat `PENDING`, `STARTED`, and `RETRY` as 'in-progress' states and continue polling. Only `SUCCESS` and `FAILURE` are terminal.

---

## 8. Monitoring

Flower is a lightweight web UI for Celery that provides real-time visibility into the queue length, active tasks, worker status, and task history. Install and run it on the same VM:

```bash
pip install flower
celery -A celery_app flower --port=5555
```

Flower exposes a dashboard at `http://localhost:5555` (bind to `0.0.0.0` only if the VM is behind a firewall). It shows per-worker task throughput, failure rates, and queued task counts — useful for diagnosing bottlenecks and tuning concurrency.

**Key metrics to watch:**

- **Queue length** — if it grows faster than workers drain it, add concurrency or investigate task duration.
- **Worker memory usage** — if it grows per task, check for memory leaks in the task code. `worker_max_tasks_per_child` mitigates this.
- **Failure rate** — a sustained failure rate indicates an upstream dependency issue (database timeouts, external API errors).

---

## 9. Future Scaling Path

The architecture introduced here is designed to scale without refactoring. If the current single VM ever needs more headroom, the following steps can be taken incrementally:

1. **Increase worker concurrency** — add more Celery worker processes on the same VM by increasing `--concurrency` or running multiple worker instances targeting the same Redis queue.

2. **Add a second Worker VM** — because Celery workers are stateless and connect to Redis independently, a second VM running `celery -A celery_app worker` pointing at the same Redis host immediately doubles task throughput. No code changes required.

3. **Separate Redis onto its own VM** — Redis is single-threaded but extremely fast. At very high load, moving it to a dedicated VM eliminates I/O contention with the API server and worker.

4. **Switch to WebSockets for status updates** — polling every 3 seconds works well at current scale. If the number of concurrent in-flight tasks grows significantly, replacing polling with a WebSocket or Server-Sent Events push from the worker reduces status-check overhead to zero.

### No architectural rewrite required

Every scaling step above is additive. The FastAPI codebase, task logic, and Redis configuration remain unchanged. Workers are added or moved without modifying a single line of application code.

---

## 10. Dependency Summary

| Package | Install / Status | Purpose |
|---------|------------------|---------|
| `celery[redis]` | `pip install celery[redis]` | Task queue framework + Redis transport |
| `fastapi` | Already installed | ASGI web framework |
| `uvicorn` / `gunicorn` | Already installed | ASGI server |
| `redis` | Already on VM | Message broker and result backend |
| `gevent` (optional) | `pip install gevent` | Required only for I/O-bound worker pool |
| `flower` (optional) | `pip install flower` | Worker monitoring dashboard |

---

## Quick Start Checklist

- [ ] Copy `celery_app.py`, `tasks.py`, `main.py` to your project
- [ ] Update `broker` and `backend` Redis connection strings if needed
- [ ] Replace the placeholder task logic in `tasks.py` with your actual code
- [ ] Install dependencies: `pip install celery[redis]`
- [ ] Test locally: `celery -A celery_app worker --loglevel=debug`
- [ ] Create `/etc/systemd/system/celery-worker.service` with your paths
- [ ] Enable and start: `systemctl enable celery-worker && systemctl start celery-worker`
- [ ] Verify status: `systemctl status celery-worker` and `celery -A celery_app inspect active`
- [ ] Update front-end to call `POST /tasks` and poll `GET /tasks/{task_id}`
- [ ] (Optional) Install Flower for monitoring: `pip install flower`

---

**For more information:**

- Celery docs: https://docs.celeryq.dev/
- FastAPI async: https://fastapi.tiangolo.com/async-sql-databases/
- Redis persistence: https://redis.io/docs/management/persistence/
